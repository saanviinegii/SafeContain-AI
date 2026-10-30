# ENTERPRISE DEPLOYMENT & OPERATIONS GUIDE
## SafeContain AI — Multi-Environment Deployment Architecture
**Document Version:** 1.0.0  

---

## 1. Supported Deployment Topologies

1. **Bare-Metal / Virtual Machine (Native):**
   - Direct execution via Python 3.11+ virtual environment and Node.js Nginx/systemd services.
   - Ideal for isolated air-gapped forensic labs and evaluation environments.
2. **Containerized (Docker Compose):**
   - Full-stack compose deployment mounting Backend, Frontend, Neo4j (APOC), and PostgreSQL with automated health probes.
3. **Cloud Native (Kubernetes / OpenShift):**
   - Multi-replica Deployment profiles in `k8s/` with ConfigMaps, ClusterIP, and LoadBalancer services for high-availability enterprise SOCs.

---

## 2. Step-by-Step Deployment Procedures

### Production Docker Compose Deployment
```bash
# 1. Clone repository
git clone https://github.com/safecontain/safecontain-ai.git
cd safecontain-ai

# 2. Configure environment
cp .env.example .env
# Edit .env with production passwords and TLS keys

# 3. Build and launch services
docker-compose up -d --build

# 4. Verify service health
docker-compose ps
curl -f http://localhost:8000/api/v1/health
```

### Kubernetes Deployment
```bash
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl rollout status deployment/safecontain-backend
```
