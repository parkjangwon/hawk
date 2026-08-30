def f():
    try:
        work()
        # ruleid: korea.py.improper-exception
    except Exception:
        pass
    # ok: korea.py.improper-exception
    try:
        work()
    except Exception as e:
        logger.error(e)
