package  policy_ff9bd0db_f407_4f32_b7a1_6bc757125e29

import data.helper

Authorize = result { 

  # Match any of the Rules
  result := MatchAnyRule

}

MatchAnyRule() = {"action" : "deny", "rule" : "acaa81bc-b0af-43b6-b486-4ab7778d5f98" } {
MatchItemToExactFn1 := {
"exact" : {`1`, `2`}
}
MatchItemToExactFn1["exact"][input["CLIENT"]["ASN"]]
#MatchItemToExactFn1.exact[input.CLIENT.ASN]
}
