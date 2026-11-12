# The base image by digest: a tag can be moved to other content, a digest cannot. Dependabot proposes
# the new digest when the tag is rebuilt (.github/dependabot.yml).
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

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
