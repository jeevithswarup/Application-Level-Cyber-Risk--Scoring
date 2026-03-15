def apply_security_action(user):

    score = user.risk_score

    if score <= 30:
        user.account_status = "active"

    elif score <= 60:
        user.account_status = "restricted"

    elif score > 60:
        user.account_status = "blocked"

    user.save()