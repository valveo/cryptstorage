# The base image by digest: a tag can be moved to other content, a digest cannot. Dependabot proposes
# the new digest when the tag is rebuilt (.github/dependabot.yml).
FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

WORKDIR /app

# Install dependencies
# requirements.lock: every package, also the indirect ones, at a fixed version with its hash
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

# Copy source
COPY . .

# Non-root user for the API process
RUN useradd -r -s /bin/false apiuser
USER apiuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
