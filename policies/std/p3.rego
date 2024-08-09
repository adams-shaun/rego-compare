package  policy_71c9563b_ac0c_4e0c_a7a8_77bf7e9cd1cc

import data.helper

Authorize = result { 

  # Match any of the Rules
  result := MatchAnyRule

}




MatchAnyRule() = {"action" : "deny", "rule" : "a6ad88e3-8cf3-4e35-9491-a0ff894dc943" } {
MatchLabelExpressionAnyFn3 := {
"any" : {`AU`, `KP`, `KR`}
}
MatchLabelExpressionAnyFn3["any"][input["CLIENT"]["LABEL"]["geoip.ves.io/country"]]

}