package  policy_c2af3c62_344e_4ec0_a759_6c7a36696c4d

import data.helper

Authorize = result { 

  # Match any of the Rules
  result := MatchAnyRule

}




MatchAnyRule() = {"action" : "deny", "rule" : "3e94ef55-8c87-4597-a9b5-5f50dd226bfd" } {
MatchIpPrefixFn2 := {
"ip_prefix" : [`192.168.30.0/24`, `192.168.40.0/24`]
}
net.cidr_contains(MatchIpPrefixFn2["ip_prefix"][_],input["CLIENT"]["ADDRESS"])

}