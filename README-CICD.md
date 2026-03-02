# BeeWAF — Pipeline CI/CD avec Jenkins et ArgoCD

## 📋 Table des matières

1. [Architecture CI/CD](#architecture-cicd)
2. [Architecture Cluster DPC](#architecture-cluster-dpc)
3. [Prérequis](#prérequis)
4. [Installation de Jenkins](#installation-de-jenkins)
5. [Installation d'ArgoCD](#installation-dargocd)
6. [Configuration du Pipeline](#configuration-du-pipeline)
7. [Workflow GitOps](#workflow-gitops)
8. [Commandes utiles](#commandes-utiles)

---

## 🏗️ Architecture CI/CD

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ARCHITECTURE CI/CD BeeWAF                          │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────┐
                              │   Développeur   │
                              │   (git push)    │
                              └────────┬────────┘
                                       │
                                       ▼
                         ┌─────────────────────────────┐
                         │     Git Repository          │
                         │  (GitHub/GitLab/Bitbucket)  │
                         │                             │
                         │  - beewaf (code source)     │
                         │  - beewaf-k8s-manifests     │
                         └─────────────┬───────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
                    ▼                  ▼                  ▼
         ┌──────────────────┐  ┌──────────────┐  ┌──────────────────┐
         │     JENKINS      │  │   ArgoCD     │  │   Webhook        │
         │     (CI)         │  │   (CD)       │  │   Notifications  │
         │                  │  │              │  │                  │
         │  1. Checkout     │  │ Surveille    │  │ Slack/Email      │
         │  2. Tests        │  │ le repo      │  │                  │
         │  3. Build Image  │  │ manifests    │  └──────────────────┘
         │  4. Push Registry│  │              │
         │  5. Update YAML  │  │ Sync auto    │
         └────────┬─────────┘  └──────┬───────┘
                  │                   │
                  ▼                   ▼
         ┌──────────────────┐  ┌──────────────────┐
         │ Docker Registry  │  │ Kubernetes       │
         │                  │  │ Cluster          │
         │ beewaf:tag       │  │                  │
         └──────────────────┘  │ ┌──────────────┐ │
                               │ │ Namespace    │ │
                               │ │ beewaf       │ │
                               │ │              │ │
                               │ │ ┌──────────┐ │ │
                               │ │ │ BeeWAF   │ │ │
                               │ │ │ Pod(s)   │ │ │
                               │ │ └──────────┘ │ │
                               │ └──────────────┘ │
                               └──────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           FLUX DE DÉPLOIEMENT                                │
└─────────────────────────────────────────────────────────────────────────────┘

  develop branch ──► Jenkins Build ──► Docker Image ──► ArgoCD Sync ──► DEV
                                                                                    │
  main branch ────► Jenkins Build ──► Docker Image ──► ArgoCD Sync ──► PROD
                                         │                    │
                                         │                    └──► Manual Approval
                                         │
                                         └──► Update kustomization.yaml
                                              in beewaf-k8s-manifests repo
```

---

## 🏢 Architecture Cluster DPC

### Topologie du cluster

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE CLUSTER DPC                                  │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────┐
                              │   Poste Kali    │
                              │  (Développeur)  │
                              └────────┬────────┘
                                       │ SSH -p 258
                                       ▼
                         ┌─────────────────────────────┐
                         │      PASSERELLE             │
                         │  passrelle.dpc.com.tn       │
                         │  Ubuntu 22.04 (Proxmox)     │
                         └─────────────┬───────────────┘
                                       │ SSH -p 8520
                                       ▼
                         ┌─────────────────────────────┐
                         │         HAPROXY             │
                         │  haproxystage.dpc.com.tn    │
                         │  IP: 207.180.211.157        │
                         │  Ubuntu 22.04               │
                         │  - HAProxy Load Balancer    │
                         │  - Nginx Ingress Controller │
                         └─────────────┬───────────────┘
                                       │ SSH
                                       ▼
              ┌─────────────────────────────────────────────────┐
              │              CLUSTER KUBERNETES                  │
              │              (MicroK8s / K8s v1.29)              │
              │                                                  │
              │  ┌──────────────┐  ┌──────────────┐              │
              │  │   Master1    │  │   Master2    │              │
              │  │192.168.90.10 │  │192.168.90.11 │              │
              │  │TESTHAmaster1 │  │TESTHAmaster2 │              │
              │  └──────────────┘  └──────────────┘              │
              │                                                  │
              │  ┌──────────────┐  ┌──────────────┐              │
              │  │   Master3    │  │   Worker1    │              │
              │  │192.168.90.12 │  │192.168.90.20 │              │
              │  │TESTHAmaster3 │  │ TESTHAworker │              │
              │  └──────────────┘  └──────────────┘              │
              │                                                  │
              │  Namespaces:                                     │
              │  - beewaf (WAF)                                  │
              │  - idts-test (Application protégée)              │
              │  - argocd (GitOps)                               │
              │  - jenkins (CI)                                  │
              └─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                    FLUX DE DÉPLOIEMENT                                       │
└─────────────────────────────────────────────────────────────────────────────┘

  1. Build Image (Kali)
       │
       ▼
  2. docker save → beewaf.tar.gz
       │
       ▼
  3. Transfert SSH chaîné:
       Kali → Passerelle → HAProxy → Master1
       │
       ▼
  4. ctr import (containerd namespace k8s.io)
       │
       ▼
  5. kubectl rollout restart deployment/beewaf
```

### Connexion au cluster

```bash
# Depuis Kali
ssh -p 258 baha@passrelle.dpc.com.tn

# Depuis Passerelle → HAProxy
ssh -p 8520 baha@haproxystage.dpc.com.tn

# Depuis HAProxy → Master
ssh baha@192.168.90.10

# Passer en root sur le Master
sudo su
```

### Commandes kubectl sur le cluster

```bash
# Vérifier les nœuds
kubectl get nodes -o wide

# Vérifier les pods BeeWAF
kubectl get pods -n beewaf -o wide

# Vérifier les services
kubectl get svc -A

# Vérifier les ingress
kubectl get ingress -A
```

---

## 📊 État actuel du cluster DPC

| Composant | Statut | Version | Namespace |
|-----------|--------|---------|-----------|
| **Kubernetes** | ✅ Actif | v1.29.15 | - |
| **ArgoCD** | ✅ Installé | - | argocd |
| **Helm** | ✅ Disponible | v3.20.0 | - |
| **cert-manager** | ✅ Installé | v1.13.2 | cert-manager |
| **ingress-nginx** | ✅ Installé | 1.14.3 | ingress-nginx |
| **Jenkins** | ❌ À installer | - | - |
| **BeeWAF** | ✅ Déployé | v6.0 | beewaf |
| **ELK Stack** | ✅ Déployé | 8.11.0 | beewaf |

### Nœuds du cluster

| Nœud | Rôle | IP | CPU | Mémoire |
|------|------|-----|-----|---------|
| testhamaster1 | control-plane | 192.168.90.10 | 2 | 6GB |
| testhamaster2 | control-plane | 192.168.90.20 | - | - |
| testhamaster3 | control-plane | 192.168.90.30 | - | - |
| testhaworker1 | worker | 192.168.90.40 | - | - |
| testhaworker2 | worker | 192.168.90.50 | - | - |

### URLs configurées

| Service | URL |
|---------|-----|
| ArgoCD UI | https://argocd.dpc.com.tn |
| BeeWAF (secure) | https://secure.idts.dpc.com.tn |
| BeeWAF (dev) | https://dev.idts.dpc.com.tn |
| BeeWAF (back) | https://idts.back.dpc.com.tn |
| Kibana | https://kibana.dpc.com.tn |

---

## 📦 Prérequis

### Infrastructure requise

| Composant | Version | Description |
|-----------|---------|-------------|
| Kubernetes | ≥ 1.25 | Cluster K8s fonctionnel |
| Jenkins | ≥ 2.400 | Serveur CI |
| ArgoCD | ≥ 2.7 | GitOps operator |
| Docker Registry | - | Harbor, Docker Hub, ou privé |
| Git | - | GitHub, GitLab, ou Bitbucket |

### Outils locaux

```bash
# Vérifier les outils installés
kubectl version --client
docker --version
git --version
helm version  # optionnel
```

---

## 🚀 Installation de Jenkins

### Option 1: Jenkins sur Kubernetes (recommandé)

```bash
# 1. Créer le namespace
kubectl create namespace jenkins

# 2. Installer Jenkins avec Helm
helm repo add jenkins https://charts.jenkins.io
helm repo update

helm install jenkins jenkins/jenkins \
  --namespace jenkins \
  --set controller.serviceType=LoadBalancer \
  --set controller.installPlugins=false \
  --set controller.additionalPlugins="kubernetes:latest,workflow-aggregator:latest,git:latest,docker:latest,pipeline-stage-view:latest,credentials-binding:latest"

# 3. Récupérer le mot de passe admin
kubectl exec --namespace jenkins -it svc/jenkins -c jenkins -- /bin/cat /run/secrets/additional/chart-admin-password && echo

# 4. Port-forward pour accès local
kubectl port-forward svc/jenkins 8080:8080 -n jenkins
```

### Option 2: Jenkins sur VM (Docker)

```bash
# Sur le serveur Jenkins
docker run -d \
  --name jenkins \
  -p 8080:8080 \
  -p 50000:50000 \
  -v jenkins_home:/var/jenkins_home \
  -v /var/run/docker.sock:/var/run/docker.sock \
  jenkins/jenkins:lts

# Récupérer le mot de passe initial
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

### Configuration Jenkins requise

1. **Plugins à installer:**
   - Kubernetes Plugin
   - Docker Pipeline
   - Git Plugin
   - Pipeline: Stage View
   - Credentials Binding

2. **Credentials à configurer:**
   - `docker-registry-credentials`: Username/password pour le registry Docker
   - `git-ssh-credentials`: Clé SSH pour le repo Git des manifests

3. **Variables d'environnement globales:**
   - `DOCKER_REGISTRY`: URL du registry (ex: `docker.io` ou `harbor.company.com`)
   - `DOCKER_IMAGE_NAME`: Nom de l'image (ex: `beewaf`)
   - `GIT_MANIFESTS_REPO`: URL du repo des manifests K8s

---

## 🎯 Installation d'ArgoCD

### Installation sur Kubernetes

```bash
# 1. Créer le namespace ArgoCD
kubectl create namespace argocd

# 2. Installer ArgoCD
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# 3. Vérifier les pods
kubectl get pods -n argocd

# 4. Récupérer le mot de passe admin
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d && echo

# 5. Exposer l'UI (choisir une option)
# Option A: Port-forward
kubectl port-forward svc/argocd-server -n argocd 8080:443

# Option B: Ingress
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argocd-server-ingress
  namespace: argocd
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
      - argocd.dpc.com.tn
      secretName: argocd-tls
  rules:
    - host: argocd.dpc.com.tn
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: argocd-server
                port:
                  number: 443
EOF
```

### Configuration ArgoCD

```bash
# Installer l'CLI ArgoCD
curl -sSL -o argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
sudo install -m 555 argocd /usr/local/bin/argocd

# Se connecter
argocd login argocd.dpc.com.tn --grpc-web

# Ajouter le repo Git des manifests
argocd repo add git@github.com:votre-org/beewaf-k8s-manifests.git --ssh-private-key-path ~/.ssh/id_rsa

# Déployer le AppProject
kubectl apply -f argocd/appproject.yaml

# Déployer les Applications
kubectl apply -f argocd/application-dev.yaml
kubectl apply -f argocd/application-prod.yaml
```

---

## ⚙️ Configuration du Pipeline

### Structure des repositories Git

```
Repository 1: beewaf (code source)
├── app/
├── waf/
├── k8s/
│   ├── base/              # Manifests de base Kustomize
│   │   ├── kustomization.yaml
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── ingress.yaml
│   └── overlays/
│       ├── dev/           # Overlays pour dev
│       └── prod/          # Overlays pour prod
├── argocd/                # Manifests ArgoCD
│   ├── appproject.yaml
│   ├── application-dev.yaml
│   └── application-prod.yaml
├── Dockerfile.k8s
├── Jenkinsfile
└── requirements.txt

Repository 2: beewaf-k8s-manifests (manifests générés)
├── overlays/
│   ├── dev/
│   │   └── kustomization.yaml
│   └── prod/
│       └── kustomization.yaml
└── README.md
```

### Variables d'environnement Jenkins

Dans Jenkins → Manage Jenkins → Configure System → Global properties:

| Variable | Valeur | Description |
|----------|--------|-------------|
| `DOCKER_REGISTRY` | `docker.io` | Registry Docker |
| `DOCKER_IMAGE_NAME` | `beewaf` | Nom de l'image |
| `DOCKER_CREDENTIALS_ID` | `docker-registry-credentials` | ID du credential |
| `GIT_MANIFESTS_REPO` | `git@github.com:org/beewaf-k8s-manifests.git` | Repo manifests |
| `GIT_MANIFESTS_BRANCH` | `main` | Branche manifests |
| `GIT_CREDENTIALS_ID` | `git-ssh-credentials` | ID du credential Git |

---

## 🔄 Workflow GitOps

### Workflow de développement

```bash
# 1. Créer une branche feature
git checkout -b feature/ma-nouvelle-fonctionnalite

# 2. Développer et commiter
git add .
git commit -m "feat: ajout de ma fonctionnalité"

# 3. Pousser vers le repo
git push origin feature/ma-nouvelle-fonctionnalite

# 4. Créer une Pull Request vers develop
# → Jenkins lance le pipeline de test
# → Tests unitaires + Build + Tests d'intégration

# 5. Merger vers develop
# → Jenkins lance le pipeline complet
# → Build + Push image + Update manifests dev
# → ArgoCD synchronise automatiquement vers DEV
```

### Workflow de production

```bash
# 1. Créer une PR de develop vers main
# → Jenkins lance les tests complets

# 2. Merger vers main
# → Jenkins lance le pipeline production
# → Build + Push image + Update manifests prod
# → ArgoCD attend une validation manuelle

# 3. Valider dans ArgoCD UI
# → Cliquer "Sync" sur l'application beewaf-prod
# → Le déploiement s'effectue
```

### Schéma du workflow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         WORKFLOW GITOPS                                      │
└─────────────────────────────────────────────────────────────────────────────┘

  feature/*          develop              main
     │                  │                   │
     │    PR            │      PR           │
     ├──────────────────►├──────────────────►│
     │                  │                   │
     ▼                  ▼                   ▼
  ┌──────┐          ┌──────┐           ┌──────┐
  │ TEST │          │ DEV  │           │ PROD │
  │ ONLY │          │ AUTO │           │MANUAL│
  └──────┘          └──────┘           └──────┘
     │                  │                   │
     │                  │                   │
     ▼                  ▼                   ▼
  Tests            Deploy Auto        Deploy Manual
  Unitaires        ArgoCD Sync        ArgoCD Sync
  + Build          → beewaf-dev       → beewaf-prod
```

---

## 🛠️ Commandes utiles

### Jenkins

```bash
# Lancer un build manuellement
curl -X POST http://jenkins:8080/job/beewaf/build

# Voir le statut du dernier build
curl -s http://jenkins:8080/job/beewaf/lastBuild/api/json | jq '.result'

# Voir les logs d'un build
curl -s http://jenkins:8080/job/beewaf/lastBuild/consoleText
```

### ArgoCD

```bash
# Lister les applications
argocd app list

# Synchroniser une application
argocd app sync beewaf-dev

# Voir le statut
argocd app get beewaf-dev

# Voir les différences
argocd app diff beewaf-dev

# Historique des déploiements
argocd app history beewaf-prod

# Rollback
argocd app rollback beewaf-prod <revision>

# Forcer un refresh
argocd app refresh beewaf-dev
```

### Kubernetes

```bash
# Vérifier le déploiement
kubectl get all -n beewaf

# Voir les logs
kubectl logs -f deployment/beewaf -n beewaf

# Vérifier les événements
kubectl get events -n beewaf --sort-by='.lastTimestamp'

# Décrire le déploiement
kubectl describe deployment beewaf -n beewaf

# Scale manuel
kubectl scale deployment beewaf --replicas=3 -n beewaf

# Rollout
kubectl rollout status deployment/beewaf -n beewaf
kubectl rollout history deployment/beewaf -n beewaf
kubectl rollout undo deployment/beewaf -n beewaf
```

### Kustomize

```bash
# Prévisualiser les manifests générés
kustomize build k8s/overlays/dev
kustomize build k8s/overlays/prod

# Appliquer directement
kustomize build k8s/overlays/dev | kubectl apply -f -

# Vérifier la différence
kustomize build k8s/overlays/prod | kubectl diff -f -
```

---

## 📊 Monitoring et Alertes

### Health Checks

```bash
# Endpoint de santé BeeWAF
curl http://beewaf-svc:80/health

# Vérifier les probes
kubectl describe pod -n beewaf -l app=beewaf | grep -A5 "Liveness\|Readiness"
```

### Notifications ArgoCD

Configurer les notifications Slack/Email dans `argocd-notifications-cm`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-notifications-cm
  namespace: argocd
data:
  service.slack: |
    token: $slack-token
  template.app-deployed: |
    slack:
      attachments: |
        [{
          "title": "{{.app.metadata.name}}",
          "title_link": "{{.context.argocdUrl}}/applications/{{.app.metadata.name}}",
          "color": "#18be52",
          "fields": [
          {
            "title": "Sync Status",
            "value": "{{.app.status.sync.status}}",
            "short": true
          },
          {
            "title": "Health Status",
            "value": "{{.app.status.health.status}}",
            "short": true
          }
          ]
        }]
```

---

## 🔧 Dépannage

### Problèmes courants

| Problème | Solution |
|----------|----------|
| ImagePullBackOff | Vérifier `imagePullPolicy` et le registry |
| CrashLoopBackOff | Vérifier les logs: `kubectl logs <pod>` |
| ArgoCD OutOfSync | `argocd app sync <app-name>` |
| Jenkins build échoue | Vérifier les credentials Docker |
| Sync bloqué | Vérifier les ressources K8s en erreur |

### Logs utiles

```bash
# Logs Jenkins
kubectl logs -f deployment/jenkins -n jenkins

# Logs ArgoCD
kubectl logs -f deployment/argocd-server -n argocd
kubectl logs -f deployment/argocd-repo-server -n argocd

# Logs BeeWAF
kubectl logs -f deployment/beewaf -n beewaf
```

---

## 📚 Ressources

- [Documentation Jenkins](https://www.jenkins.io/doc/)
- [Documentation ArgoCD](https://argo-cd.readthedocs.io/)
- [Documentation Kustomize](https://kustomize.io/)
- [GitOps Best Practices](https://opengitops.dev/)

---

## 👥 Contacts

- **Équipe BeeWAF**: beewaf-team@example.com
- **Support DevOps**: devops@example.com
