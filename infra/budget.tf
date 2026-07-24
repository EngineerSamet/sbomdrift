# SPDX-License-Identifier: Apache-2.0
#
# The first thing applied and the last thing destroyed. An alarm that fires at
# 80% of a $20 budget is worth more on a learning account than any amount of
# careful reasoning about what things cost, because the reasoning is what turns
# out to be wrong.

resource "aws_budgets_budget" "monthly" {
  name         = "${var.project}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_notification_email]
  }

  # Forecast as well as actual: by the time actual spend crosses the line the
  # money is already gone, whereas a forecast breach is still preventable.
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_notification_email]
  }
}
