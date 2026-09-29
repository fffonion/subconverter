#include "parser/subparser.h"
#include "generator/config/subexport.h"
#include <cassert>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

int main() {
    ProxyGroupConfigs groups;
    extra_settings settings;
    settings.nodelist = true;
    const std::string prefix = "vless://12345678-1234-1234-1234-123456789abc@192.0.2.1:443?security=reality&pbk=sample-key&sid=";
    for (const std::string short_id : {"11", "0x11", "0011", "null"}) {
        Proxy node;
        explode(prefix + short_id + "#sample", node);
        assert(node.Type == ProxyType::VLESS);
        std::vector<Proxy> nodes{node};
        std::vector<RulesetContent> rules;
        const std::string yaml = proxyToClash(nodes, "{}", rules, groups, false, settings);
        const auto reality = YAML::Load(yaml)["proxies"][0]["reality-opts"];
        assert(reality.IsMap());
        if (short_id == "null") {
            assert(!reality["short-id"]);
        } else {
            assert(reality["short-id"].as<std::string>() == short_id);
            assert(reality["short-id"].Tag() == "tag:yaml.org,2002:str" ||
                   yaml.find("short-id: \"" + short_id + "\"") != std::string::npos);
        }
    }
}
