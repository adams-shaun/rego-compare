package  policy_65747cc8_746d_439d_a7c7_e31b5ff0ec84

import data.helper

Authorize = result { 

  # Match any of the Rules
  result := MatchAnyRule

}




MatchAnyRule() = {"action" : "deny", "rule" : "269c72e8-c99d-473f-84c3-340d1f972424" } {
input["CLIENT"]["ASN"] == `12123`

} else = {"action" : "allow", "rule" : "ae215265-21ed-401c-b857-6ba1c699c70b" } {
true
}