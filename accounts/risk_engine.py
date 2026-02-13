MAX_RISK_SCORE = 100
MIN_RISK_SCORE = 0


def update_risk_score(user, points):
    user.risk_score += points

    if user.risk_score > MAX_RISK_SCORE:
        user.risk_score = MAX_RISK_SCORE

    if user.risk_score < MIN_RISK_SCORE:
        user.risk_score = MIN_RISK_SCORE

    user.save()



def failed_login_risk(user):
    update_risk_score(user, 10)


def ip_device_change_risk(user):
    update_risk_score(user, 15)


def suspicious_activity_risk(user):
    update_risk_score(user, 20)


def normal_behavior_reward(user):
    update_risk_score(user, -5)
