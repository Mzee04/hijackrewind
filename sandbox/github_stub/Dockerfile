FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml requirements.txt /app/
COPY src /app/src
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --no-deps -e .

ENV PYTHONUNBUFFERED=1
EXPOSE 8088
CMD ["python", "-m", "uvicorn", "hijackrewind.stub_app:app", "--host", "0.0.0.0", "--port", "8088"]
