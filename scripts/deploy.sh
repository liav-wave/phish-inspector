#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:?Set GCP_PROJECT_ID}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="phish-triage"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "==> Building container image..."
gcloud builds submit --tag "${IMAGE}" .

echo "==> Deploying to Cloud Run (${REGION})..."
gcloud run deploy "${SERVICE_NAME}" \
  --image "${IMAGE}" \
  --region "${REGION}" \
  --platform managed \
  --no-allow-unauthenticated \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 2 \
  --timeout 300 \
  --port 8080 \
  --set-secrets "URLSCAN_API_KEY=urlscan-api-key:latest,VIRUSTOTAL_API_KEY=virustotal-api-key:latest,GOOGLE_SAFE_BROWSING_API_KEY=google-safe-browsing-api-key:latest,ABUSEIPDB_API_KEY=abuseipdb-api-key:latest"

URL=$(gcloud run services describe "${SERVICE_NAME}" --region "${REGION}" --format "value(status.url)")
echo ""
echo "==> Deployed: ${URL}"
echo ""
echo "To grant a user access:"
echo "  gcloud run services add-iam-policy-binding ${SERVICE_NAME} \\"
echo "    --region=${REGION} \\"
echo "    --member='user:someone@yourco.com' \\"
echo "    --role='roles/run.invoker'"
