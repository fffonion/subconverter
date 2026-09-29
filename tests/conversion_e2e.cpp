#include "parser/subparser.h"
#include "generator/config/subexport.h"
#include <cassert>
#include <iostream>
#include <rapidjson/document.h>

void explodeVlessConf(std::string content, std::vector<Proxy> &nodes);
void explodeClash(YAML::Node yamlnode, std::vector<Proxy> &nodes);

int main() {
    const std::string uuid = "12345678-1234-1234-1234-123456789abc";
    Proxy vless;
    explode("vless://" + uuid + "@192.0.2.1:443?security=reality&sni=example.com&fp=chrome&pbk=abc&sid=11&type=ws&host=ws.example.com&path=%2Fws#vless", vless);
    assert(vless.Type == ProxyType::VLESS);
    assert(vless.UserId == uuid);
    assert(vless.Host == "ws.example.com");
    Proxy ipv6;
    explode("vless://" + uuid + "@[2001:db8::1]:443?security=tls#ipv6", ipv6);
    assert(ipv6.Type == ProxyType::VLESS);
    assert(ipv6.Hostname == "2001:db8::1");
    assert(ipv6.Port == 443);

    std::vector<Proxy> json_nodes;
    explodeVlessConf(R"({"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"192.0.2.2","port":443}]}}]})", json_nodes);
    assert(json_nodes.empty()); // An absent users list cannot produce a valid VLESS node.
    explodeVlessConf(R"({"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"192.0.2.2","port":443,"users":[{"id":"12345678-1234-1234-1234-123456789abc"}]}]},"streamSettings":{"network":"tcp","tcpSettings":{"header":null},"security":"reality","realitySettings":null}}]})", json_nodes);

    Proxy hy2;
    explode("hysteria2://password@192.0.2.10:8443-8450/?sni=example.com&pinSHA256=abc&up=1%20Gbps&down=200%20Mbps#hy2", hy2);
    assert(hy2.Type == ProxyType::Hysteria2);
    assert(hy2.Ports == "8443-8450");
    assert(hy2.Port == 8443);
    assert(hy2.Fingerprint == "abc");
    assert(hy2.UpSpeed == 1000);
    Proxy hopping;
    explode("hy2://sample@192.0.2.11:8443?ports=12001-13000&alpn=h3%2Ch2#hopping", hopping);
    assert(hopping.Type == ProxyType::Hysteria2);
    assert(hopping.Port == 8443);
    assert(hopping.Ports == "12001-13000");
    assert(hopping.Alpn.size() == 2);
    assert(hopping.Alpn[0] == "h3" && hopping.Alpn[1] == "h2");

    ProxyGroupConfigs groups;
    extra_settings settings;
    settings.nodelist = true;
    YAML::Node sample = YAML::Load(R"(proxies:
  - name: sample-hy2
    type: hysteria2
    server: hy2.example.com
    ports: 12001-13000
    hop-interval: 26
    password: sample-password
    bbr-profile: aggressive
    up: 30 Mbps
    down: 100 Mbps
    sni: tls.example.com
    skip-cert-verify: false
    alpn:
      - h3
)");
    std::vector<Proxy> sample_nodes;
    explodeClash(sample, sample_nodes);
    assert(sample_nodes.size() == 1);
    assert(sample_nodes[0].Group == HYSTERIA2_DEFAULT_GROUP);
    assert(sample_nodes[0].Port == 12001);
    assert(sample_nodes[0].Ports == "12001-13000");
    assert(sample_nodes[0].HopInterval == 26);
    assert(sample_nodes[0].Up == "30 Mbps");
    assert(sample_nodes[0].Down == "100 Mbps");
    assert(sample_nodes[0].Alpn.size() == 1 && sample_nodes[0].Alpn[0] == "h3");
    YAML::Node sample_output;
    proxyToClash(sample_nodes, sample_output, groups, false, settings);
    assert(sample_output["proxies"][0]["ports"].as<std::string>() == "12001-13000");
    assert(sample_output["proxies"][0]["hop-interval"].as<int>() == 26);
    assert(sample_output["proxies"][0]["bbr-profile"].IsDefined());
    assert(sample_output["proxies"][0]["bbr-profile"].as<std::string>() == "aggressive");
    YAML::Node vless_input = YAML::Load(R"(proxies:
  - {name: first, type: vless, server: first.example.com, port: 443, uuid: 12345678-1234-1234-1234-123456789abc, tls: true, network: ws, ws-opts: {path: /first, headers: {Host: ws-first.example.com}}}
  - {name: second, type: vless, server: second.example.com, port: 443, uuid: 12345678-1234-1234-1234-123456789abc, tls: true, network: ws, packet-encoding: xudp, encryption: example-encryption, alpn: [h2, http/1.1]}
)");
    std::vector<Proxy> vless_nodes;
    explodeClash(vless_input, vless_nodes);
    assert(vless_nodes.size() == 2);
    assert(vless_nodes[1].Path == "/");
    assert(vless_nodes[1].Host != "ws-first.example.com");
    YAML::Node vless_output;
    proxyToClash(vless_nodes, vless_output, groups, false, settings);
    const auto second = vless_output["proxies"][1];
    assert(second["ws-opts"]["path"].as<std::string>() == "/");
    assert(second["packet-encoding"].as<std::string>() == "xudp");
    assert(second["encryption"].as<std::string>() == "example-encryption");
    assert(second["alpn"].size() == 2);
    std::vector<Proxy> subscription_nodes;
    explodeSub("mixed-port: 7890\n" + YAML::Dump(sample), subscription_nodes);
    assert(subscription_nodes.size() == 1);
    assert(subscription_nodes[0].Remark == "sample-hy2");
    assert(subscription_nodes[0].Group == HYSTERIA2_DEFAULT_GROUP);

    std::vector<Proxy> nodes{vless, hy2};
    YAML::Node yaml;
    proxyToClash(nodes, yaml, groups, false, settings);
    const auto proxies = yaml["proxies"];
    assert(proxies && proxies.size() == 2);
    assert(proxies[0]["type"].as<std::string>() == "vless");
    assert(proxies[0]["reality-opts"]["public-key"].as<std::string>() == "abc");
    assert(proxies[1]["type"].as<std::string>() == "hysteria2");
    assert(proxies[1]["ports"].as<std::string>() == "8443-8450");
    assert(!proxies[1]["port"]);
    assert(proxies[1]["fingerprint"].as<std::string>() == "abc");
    assert(proxies[1]["up"].as<std::string>() == "1 Gbps");

    std::vector<RulesetContent> rules;
    const auto result = proxyToSingBox(nodes, "{}", rules, groups, settings);
    rapidjson::Document json;
    json.Parse(result.c_str());
    assert(!json.HasParseError());
    bool found = false;
    for (const auto& outbound : json["outbounds"].GetArray()) {
        if (std::string(outbound["type"].GetString()) != "hysteria2") continue;
        found = true;
        assert(outbound["up_mbps"].GetInt() == 1000);
        assert(outbound["down_mbps"].GetInt() == 200);
        assert(outbound["server_ports"].GetArray().Size() == 1);
        assert(std::string(outbound["server_ports"][0].GetString()) == "8443:8450");
    }
    assert(found);
    std::cout << "VLESS and Hysteria2 conversions passed\n";
}
