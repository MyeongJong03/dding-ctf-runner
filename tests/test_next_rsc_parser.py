import json

from ctf_runner.platform_generic import parse_network_json, parse_next_data, parse_rsc_payload


def test_parse_next_data_extracts_challenge_object_and_redacts_urls():
    html = """
    <script id="__NEXT_DATA__" type="application/json">
      {"props":{"pageProps":{"challenges":[
        {"id":"rev-1","title":"Reverse One","category":"rev","points":150,
         "files":[{"filename":"rev.zip","url":"/files/rev.zip?signature=secret-value"}]}
      ]}}}
    </script>
    """

    result = parse_next_data(html, base_url="https://ctf.example.com")
    rendered = json.dumps(result, sort_keys=True)

    assert result["challenge_count"] == 1
    assert result["challenges"][0]["challenge_id"] == "rev-1"
    assert result["challenges"][0]["has_files"] is True
    assert "secret-value" not in rendered
    assert "?signature=" not in rendered


def test_parse_rsc_payload_extracts_next_flight_chunks():
    chunk = json.dumps(
        {
            "problems": [
                {
                    "id": "pwn-1",
                    "title": "Pwn One",
                    "category": "pwn",
                    "points": 300,
                    "files": [{"name": "pwn.zip", "url": "/files/pwn.zip?token=signed"}],
                }
            ]
        }
    )
    payload = f"self.__next_f.push([1,{json.dumps(chunk)}]);"

    challenges = parse_rsc_payload(payload, base_url="https://ctf.example.com")
    rendered = json.dumps(challenges, sort_keys=True)

    assert challenges[0]["challenge_id"] == "pwn-1"
    assert challenges[0]["file_count"] == 1
    assert "token=signed" not in rendered


def test_parse_network_json_extracts_challenge_like_object():
    challenges = parse_network_json(
        {
            "data": {
                "tasks": [
                    {
                        "uuid": "crypto-1",
                        "name": "Crypto One",
                        "category": "crypto",
                        "score": "250",
                        "solves": 7,
                    }
                ]
            }
        },
        base_url="https://ctf.example.com",
    )

    assert challenges[0]["challenge_id"] == "crypto-1"
    assert challenges[0]["points"] == 250


def test_json_parsing_is_bounded():
    payload = {"challenges": [{"id": f"item-{index}", "name": f"Item {index}", "points": index} for index in range(600)]}

    challenges = parse_network_json(payload, base_url="https://ctf.example.com")

    assert len(challenges) == 500
    assert "item-499" in {item["challenge_id"] for item in challenges}
    assert "item-500" not in {item["challenge_id"] for item in challenges}
