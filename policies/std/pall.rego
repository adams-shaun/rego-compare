package  policy_ff9bd0db_f407_4f32_b7a1_6bc757125e29


default Authorize = {"action" : "allow", "rule" : "ae215265-21ed-401c-b857-6ba1c699c70b" }
Authorize = result { 
  # Match any of the Rules
  result := MatchAnyRule
}

MatchAnyRule() = {"action" : "deny", "rule" : "acaa81bc-b0af-43b6-b486-4ab7778d5f98" }  {
	pewp := {`1`, `2`}
    pewp[input.CLIENT.ASN]
} else = {"action" : "deny", "rule" : "3e94ef55-8c87-4597-a9b5-5f50dd226bfd" } {
	pewp := [`192.168.30.0/24`, `192.168.40.0/24`]
    net.cidr_contains(pewp[_],input["CLIENT"]["ADDRESS"])
} else = {"action" : "deny", "rule" : "a6ad88e3-8cf3-4e35-9491-a0ff894dc943" } {
	pewp := {`AU`, `KP`, `KR`}
    pewp[input["CLIENT"]["LABEL"]["geoip.ves.io/country"]]
} else = {"action" : "deny", "rule" : "8f2017ce-f7ef-4956-9334-088e942b1048"} {
	pewp := {`098f55e27d8c4b0a590102cbdb3a5f3a`, `16efcf0e00504ddfedde13bfea997952`, `2092e1fffb45d7e4a19a57f9bc5e203a`, `20dd18bdd3209ea718989030a6f93364`, `29085f03f8e8a03f0b399c5c7cf0b0b8`, `3d89c0dfb1fa44911b8fa7523ef8dedb`, `46efd49abcca8ea9baa932da68fdb529`, `550dce18de1bb143e69d6dd9413b8355`, `5e573c9c9f8ba720ef9b18e9fce2e2f7`, `698e36219f3979420fa2581b21dac7ec`, `7691297bcb20a41233fd0a0baa0a3628`, `83e04bc58d402f9633983cbf22724b02`, `8498fe4268764dbf926a38283e9d3d8f`, `849b04bdbd1d2b983f6e8a457e0632a8`, `8991a387e4cc841740f25d6f5139f92d`, `92579701f145605e9edc0b01a901c6d5`, `93d056782d649deb51cda44ecb714bb0`, `9c2589e1c0e9f533a022c6205f9719e1`, `b13d01846ad7a14a70bf030a16775c78`, `b2b61db7b9490a60d270ccb20b462826`, `b8f81673c0e1d29908346f3bab892b9b`, `bc6c386f480ee97b9d9e52d472b772d8`, `d551fafc4f40f1dec2bb45980bfa9492`, `e330bca99c8a5256ae126a55c4c725c5`, `f6fd83a21f9f3c5f9ff7b5c63bbc179d`, `fb58831f892190644fe44e25bc830b45`}
	pewp[input["CLIENT"]["TLS_FINGERPRINT"]]
} else = {"action" : "deny", "rule" : "269c72e8-c99d-473f-84c3-340d1f972424" } {
	input["CLIENT"]["ASN"] == `12123`
} 

