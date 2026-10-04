"""Each real-world scenario's headline result, pinned."""
import contextlib
import io
import runpy
from pathlib import Path

import pytest

RT = Path(__file__).resolve().parent.parent / "realtime"


@pytest.fixture(scope="module")
def out():
    result = {}
    for p in sorted(RT.glob("rt*.py")):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            runpy.run_path(str(p), run_name="__main__")
        result[p.stem] = buf.getvalue()
    return result


def test_rt01_secrets_need_house_recognizers(out):
    o = out["rt01_pasted_secrets"]
    default, house = o.split("== with house recognizers")
    assert "SECRET" not in default and house.count("SECRET") == 3
    assert "source code detected as sensitive: False" in o


def test_rt02_link_guard(out):
    o = out["rt02_link_exfiltration"]
    assert o.count("still leaks: True") == 3
    assert "link, base64    removed ['attacker.example']" in o


def test_rt03_stream(out):
    o = out["rt03_streaming_split"]
    assert o.count("SSN reached the user: True") == 1
    assert o.count("SSN reached the user: False") == 1


def test_rt04_cross_tenant(out):
    o = out["rt04_cross_tenant"]
    assert "globex's agent reveals acme's token: Maria Garcia" in o
    assert "globex reveals PERSON_001: John Smith" in o


def test_rt05_trifecta(out):
    o = out["rt05_lethal_trifecta"]
    assert "PR opened; public now holds" in o
    assert "stopped: open_public_pr" in o


def test_rt06_invented_token(out):
    o = out["rt06_invented_token"]
    assert "Compared with Maria Garcia" in o
    assert "refused_not_in_request" in o


def test_rt07_trace(out):
    assert out["rt07_trace_capture"].count("holds the raw SSN: False") == 2


def test_rt08_canary(out):
    o = out["rt08_canary_sinks"]
    assert "canary-0417@URL_001valid" in o        # the gap it found
    house = o.split("== guarded, house detector ==")[1]
    assert house.count("reached: none") == 2


def test_rt09_discover(out):
    o = out["rt09_discover_share"]
    assert "crm_export.csv         suggested label: restricted" in o
    assert "team_wiki.md           suggested label: internal" in o


def test_rt10_multilingual(out):
    o = out["rt10_multilingual"]
    assert "DATE_TIME '12345678Z'" in o and "ES_NIF '12345678Z'" in o
    assert "PERSON 'Erstattung'" in o
