
def read(session):
    with open(session.configuration) as lines:
        for line in lines:
            variable = line.strip().lower().split("=")[0]
            value = ''.join(line.strip().split("=")[1::])
            setattr(session, variable, value)
    return session
