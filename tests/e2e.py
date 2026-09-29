"""Exercise the packaged backend through its HTTP conversion endpoint."""
import base64
import json
import os
import subprocess
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path(os.environ.get("SUBCONVERTER_PACKAGE", ROOT / "subconverter"))
PORT = int(os.environ.get("SUBCONVERTER_TEST_PORT", "25500"))
URL = f"http://127.0.0.1:{PORT}"


class ConversionE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.process = subprocess.Popen([str(PACKAGE / "subconverter")], cwd=PACKAGE,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(60):
            if cls.process.poll() is not None:
                raise RuntimeError(f"backend exited: {cls.process.stderr.read().decode()}")
            try:
                with urlopen(URL + "/version", timeout=1) as response:
                    if response.status == 200:
                        return
            except OSError:
                time.sleep(0.25)
        cls.process.terminate()
        raise RuntimeError("backend did not become ready")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.process.stderr.close()

    def convert(self, target, source):
        with urlopen(URL + "/sub?" + urlencode({"target": target, "url": source}), timeout=15) as response:
            return response.read().decode()

    def test_vless_reality_and_ws(self):
        source = ("vless://12345678-1234-1234-1234-123456789abc@192.0.2.1:443"
                  "?security=reality&sni=example.com&fp=chrome&pbk=abc&sid=11"
                  "&type=ws&host=ws.example.com&path=%2Fws#vless")
        output = self.convert("clash", source)
        for expected in ("type: vless", "uuid: 12345678-1234-1234-1234-123456789abc",
                         "servername: example.com", "client-fingerprint: chrome",
                         "public-key: abc", "ws.example.com"):
            self.assertIn(expected, output[:1500], expected)
        self.assertRegex(output[:1500], r'short-id: (?:!<tag:yaml.org,2002:str> )?["\']?11["\']?')

    def test_vless_clash_fields_and_ws_isolation(self):
        sample = ("proxies:\n"
                  "  - {name: first, type: vless, server: first.example.com, port: 443, uuid: 12345678-1234-1234-1234-123456789abc, tls: true, network: ws, ws-opts: {path: /first, headers: {Host: ws-first.example.com}}}\n"
                  "  - {name: second, type: vless, server: second.example.com, port: 443, uuid: 12345678-1234-1234-1234-123456789abc, tls: true, network: ws, packet-encoding: xudp, encryption: example-encryption, alpn: [h2, http/1.1]}\n")
        source = "data:text/plain;base64," + base64.b64encode(sample.encode()).decode()
        output = self.convert("clash", source)
        self.assertEqual(output.count("/first"), 1)
        for expected in ("packet-encoding: xudp", "encryption: example-encryption", "alpn:"):
            self.assertIn(expected, output)

    def test_hysteria2_port_range_fingerprint_and_bandwidth(self):
        source = ("hysteria2://password@192.0.2.10:8443-8450/"
                  "?sni=example.com&pinSHA256=abc&up=1%20Gbps&down=200%20Mbps#hy2")
        clash = self.convert("clash", source)
        for expected in ("type: hysteria2", "ports: 8443-8450", "fingerprint: abc",
                         "up: 1 Gbps", "down: 200 Mbps"):
            self.assertIn(expected, clash[:1500], expected)
        singbox = json.loads(self.convert("singbox", source))
        outbound = next(node for node in singbox["outbounds"] if node["type"] == "hysteria2")
        self.assertEqual(outbound["up_mbps"], 1000)
        self.assertEqual(outbound["down_mbps"], 200)
        self.assertEqual(outbound["server_ports"], ["8443:8450"])

    def test_hysteria2_clash_subscription(self):
        sample = ("proxies:\n"
                  "  - name: sample-hy2\n"
                  "    type: hysteria2\n"
                  "    server: hy2.example.com\n"
                  "    ports: 12001-13000\n"
                  "    hop-interval: 26\n"
                  "    password: sample-password\n"
                  "    bbr-profile: aggressive\n"
                  "    up: 30 Mbps\n"
                  "    down: 100 Mbps\n"
                  "    obfs: gecko\n"
                  "    obfs-min-packet-size: 512\n"
                  "    obfs-max-packet-size: 1200\n"
                  "    sni: tls.example.com\n"
                  "    skip-cert-verify: false\n"
                  "    alpn: [h3, h2]\n")
        source = "data:text/plain;base64," + base64.b64encode(sample.encode()).decode()
        output = self.convert("clash", source)
        for expected in ("name: sample-hy2", "ports: 12001-13000", "hop-interval: 26",
                         "bbr-profile: aggressive", "up: 30 Mbps", "down: 100 Mbps",
                         "tls.example.com", "h3", "h2", "obfs-min-packet-size: 512",
                         "obfs-max-packet-size: 1200"):
            self.assertIn(expected, output[:1600], expected)


if __name__ == "__main__":
    unittest.main()
