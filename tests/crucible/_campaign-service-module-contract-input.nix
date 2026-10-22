##! Source-backed campaign settings for the isolated module contract check.
##!
##! The check supplies explicit valid and invalid documents through a named
##! argument. The production system evaluator still validates the complete
##! configuration; this module starts no service and issues no resource owner.
{campaignServiceContractInput, ...}: {
  aos.crucibleCampaign = campaignServiceContractInput;
}
