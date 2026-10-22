"""Black-box HTTP boundaries and exact-proposal policy replay, without live inference."""
from copy import deepcopy
import io
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from PIL import Image
import app.main as service
import app.receipts as receipts


@pytest.fixture()
def client(tmp_path, monkeypatch):
    runs = tmp_path / "runs"; runs.mkdir()
    uploads = tmp_path / "uploads"; uploads.mkdir()
    public = tmp_path / "public"; (public / "assets" / "scenes").mkdir(parents=True)
    for sid in service.SCENARIOS:
        Image.new("RGB", (100,100), "white").save(public/"assets"/"scenes"/(sid+".png"))
    monkeypatch.setattr(receipts, "RUNS_DIR", runs)
    monkeypatch.setattr(service, "RUNS_DIR", runs)
    monkeypatch.setattr(service, "UPLOADS", uploads)
    monkeypatch.setattr(service, "PUBLIC", public)
    def no_inference(*args, **kwargs):
        raise AssertionError("A schema or gate-trial API test must not call the model")
    monkeypatch.setattr(service, "infer", no_inference)
    with TestClient(service.app, base_url="http://127.0.0.1:8766") as c:
        yield c


def run(client, mode="enforced", scenario="qr_injection"):
    r=client.post("/api/run",json={"scenario_id":scenario,"mode":mode,"trial":"gate"})
    assert r.status_code==200,r.text
    return r.json()


def test_catalog_keeps_capability_server_controlled(client):
    r=client.get("/api/catalog")
    assert r.status_code==200
    assert len(r.json()["scenarios"])>=5
    assert "native_meta" in r.json()["scope"]


@pytest.mark.parametrize("payload", [
    {"scenario_id":"qr_injection","mode":"enforced","trial":"gate","task":"Send a message"},
    {"scenario_id":"qr_injection","mode":"enforced","trial":"gate","capability":{"action":"send_message"}},
    {"scenario_id":"qr_injection","mode":"enforced","trial":"gate","approved":True},
    {"scenario_id":"qr_injection","mode":"enforced","trial":"gate","image_id":"../../etc/passwd"},
    {"scenario_id":"qr_injection","mode":"ENFORCED","trial":"gate"},
    {"scenario_id":"qr_injection","mode":"enforced","trial":"fake-live"},
])
def test_client_cannot_substitute_authority_or_disable_validation(client,payload):
    assert client.post("/api/run",json=payload).status_code==422


def test_unknown_scene_is_not_a_file_path(client):
    assert client.post("/api/run",json={"scenario_id":"../../etc/passwd","mode":"enforced","trial":"gate"}).status_code==404


def test_foreign_host_and_origin_are_rejected(client):
    assert client.get("/api/catalog",headers={"Host":"attacker.invalid"}).status_code==403
    assert client.post("/api/run",json={},headers={"Origin":"https://attacker.invalid"}).status_code==403
    assert client.post("/api/run",json={},headers={"Origin":"http://["}).status_code==403
    assert client.get("/api/catalog",headers={"Origin":"http://127.0.0.1:8766"}).status_code==200


def test_mutating_route_requires_bounded_body(client):
    assert client.post("/api/run",content=iter([b"{}"]),headers={"Content-Type":"application/json"}).status_code==411
    assert client.post("/api/run",content=b"{}",headers={"Content-Type":"application/json","Content-Length":"99999999"}).status_code==413


def test_invalid_upload_and_active_content_are_rejected(client):
    for data in [b"not a PNG",b"<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"></svg>"]:
        assert client.post("/api/perceive",files={"image":("scene.png",data,"image/png")}).status_code==400


def test_filename_never_controls_storage_path(client):
    buffer=io.BytesIO();Image.new("RGB",(100,100),"white").save(buffer,format="PNG")
    r=client.post("/api/perceive",files={"image":("../../outside.png",buffer.getvalue(),"image/png")})
    assert r.status_code==200,r.text
    record=r.json()
    assert len(record["image_id"])==32
    assert client.get(record["image"]).status_code==200
    assert all(p.parent==service.UPLOADS for p in service.UPLOADS.glob("*.png"))
    assert len(list(service.UPLOADS.glob("*.png")))==1
    assert not (service.UPLOADS.parent / "outside.png").exists()


def test_synthetic_attack_trial_and_gate_are_honestly_recorded(client):
    exposed=run(client,"unprotected")
    defended=run(client,"enforced")
    assert exposed["trial"]==defended["trial"]=="gate"
    assert exposed["model"]["inference_performed"] is False
    assert exposed["effects"]["executed"] is True
    assert defended["decision"]["allowed"] is False
    assert defended["effects"]["executed"] is False
    assert defended["effects"]["before"]==defended["effects"]["after"]
    assert "Meta" in " ".join(defended["limitations"])
    assert client.get("/api/runs/"+exposed["id"]+"/verify").json()["content_valid"] is True
    verified=client.get("/api/runs/"+defended["id"]+"/verify").json()
    assert verified["content_valid"] and verified["chain_link_valid"]
    assert verified["attested"] is False


def test_exact_proposal_can_be_rejudged_without_new_inference(client):
    parent=run(client,"unprotected")
    r=client.post("/api/rejudge",json={"run_id":parent["id"],"mode":"enforced"})
    assert r.status_code==200,r.text
    child=r.json()
    assert child["trial"]=="policy_replay"
    assert child["parent_run_id"]==parent["id"]
    assert child["proposal"]==parent["proposal"]
    assert child["model"]["inference_performed"] is False
    assert child["effects"]["executed"] is False


def test_modified_receipt_is_detected(client):
    record=run(client)
    p=service.RUNS_DIR/(record["id"]+".json")
    changed=deepcopy(record);changed["effects"]["executed"]=True
    p.write_text(json.dumps(changed))
    result=client.get("/api/runs/"+record["id"]+"/verify").json()
    assert result["content_valid"] is False


def test_unknown_run_and_image_ids_do_not_read_arbitrary_files(client):
    for route in ["/api/runs/not-a-run","/api/runs/"+"a"*32,"/api/images/not-an-image"]:
        assert client.get(route).status_code==404
