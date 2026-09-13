# Airflow with the analytics dependencies baked in.
#
# The alternative — _PIP_ADDITIONAL_REQUIREMENTS — reinstalls pyarrow and duckdb on every
# container start, which turns a 5-second restart into a 3-minute one and silently drifts
# between the scheduler and the webserver. Building the image once is what a real deployment
# does, and it makes the dependency set an artifact rather than an environment variable.
#
# Build context is the repo root so this reads analytics/requirements.txt directly. One
# requirements file, not two that drift apart.
FROM apache/airflow:2.10.5-python3.11

COPY analytics/requirements.txt /tmp/requirements-analytics.txt

# Installed as the airflow user, not root: the image drops privileges at runtime and anything
# pip writes as root would be unreadable to the scheduler.
USER airflow
RUN pip install --no-cache-dir -r /tmp/requirements-analytics.txt
