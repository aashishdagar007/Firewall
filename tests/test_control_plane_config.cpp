#include <gtest/gtest.h>
#include "engine/control_plane.hpp"

TEST(CloudConfigParserTest, ParsesCompleteVersionOneConfig) {
    const std::string text = R"json({
        "_comment": "local config",
        "schema": 1,
        "magic_bytes": "ae61571c70b2d4f8",
        "rate_limit_pps": 1000,
        "default_policy": "BLOCK",
        "rules": [{
            "action": "ALLOW", "proto": "TCP", "src_ip": "10.0.0.0/8",
            "dst_ip": "*", "dst_port": 443, "description": "HTTPS"
        }],
        "geo_blocks": [{"cidr": "192.0.2.0/24", "label": "example"}],
        "emergency_shutdown": false
    })json";

    fw::CloudConfig config;
    ASSERT_TRUE(fw::CloudConfigParser::parse(text, config));
    EXPECT_EQ(config.schema, 1);
    EXPECT_EQ(config.rate_limit_pps, 1000u);
    EXPECT_EQ(config.default_policy, "BLOCK");
    ASSERT_EQ(config.rules.size(), 1u);
    EXPECT_EQ(config.rules[0].action, fw::Action::ALLOW);
    EXPECT_EQ(config.rules[0].proto, fw::Proto::TCP);
    EXPECT_EQ(config.rules[0].dst_port_start, 443);
    ASSERT_EQ(config.geo_blocks.size(), 1u);
    EXPECT_EQ(config.geo_blocks[0].cidr, "192.0.2.0/24");
    EXPECT_FALSE(config.config_hash.empty());
}

TEST(CloudConfigParserTest, RejectsMalformedJsonAndUnknownFields) {
    fw::CloudConfig config;
    EXPECT_FALSE(fw::CloudConfigParser::parse(R"({"schema":1,)" , config));
    EXPECT_FALSE(fw::CloudConfigParser::parse(
        R"({"schema":1,"unexpected":true})", config));
    EXPECT_FALSE(fw::CloudConfigParser::parse(
        R"({"schema":1,"schema":1})", config));
}

TEST(CloudConfigParserTest, RejectsInvalidValuesInsteadOfSkippingRules) {
    fw::CloudConfig config;
    EXPECT_FALSE(fw::CloudConfigParser::parse(
        R"({"schema":1,"rules":[{"action":"BLOCK","proto":"TCP","src_ip":"*","dst_ip":"*","dst_port":70000}]})",
        config));
    EXPECT_FALSE(fw::CloudConfigParser::parse(
        R"({"schema":1,"geo_blocks":[{"cidr":"10.0.0.0/33"}]})",
        config));
}

TEST(CloudConfigParserTest, RejectsWrongTypesAndUnsupportedSchema) {
    fw::CloudConfig config;
    EXPECT_FALSE(fw::CloudConfigParser::parse(
        R"({"schema":2,"rules":[]})", config));
    EXPECT_FALSE(fw::CloudConfigParser::parse(
        R"({"schema":1,"rate_limit_pps":"1000"})", config));
    EXPECT_FALSE(fw::CloudConfigParser::parse(
        R"({"schema":1,"rules":[{"action":"BLOCK","proto":"SCTP","src_ip":"*","dst_ip":"*"}]})",
        config));
}
