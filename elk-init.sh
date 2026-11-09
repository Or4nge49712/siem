#!/usr/bin/env bash
# À lancer une fois après "docker compose up -d", depuis /opt/elk : bash elk-init.sh
# Donne au compte kibana_system le mot de passe du .env pour que Kibana puisse se connecter.
set -euo pipefail
cd "$(dirname "$0")"
set -a; source .env; set +a

ES="http://${LAB_IP}:9200"
echo "Attente d'Elasticsearch sur $ES ..."
until curl -s -u "elastic:${ELASTIC_PASSWORD}" "$ES/_cluster/health" | grep -qE '"status":"(green|yellow)"'; do
  sleep 5
done

curl -s -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" \
  -X POST "$ES/_security/user/kibana_system/_password" \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}" && echo
echo "Mot de passe kibana_system défini. Kibana sera prêt d'ici 1 à 2 minutes : docker logs -f kibana"
curl -s -u "elastic:${ELASTIC_PASSWORD}" "$ES" | jq '.version.number'
