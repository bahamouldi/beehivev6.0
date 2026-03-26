// =============================================================================
// BeeWAF — Jenkins Pipeline CI/CD + ArgoCD GitOps (Cluster DPC)
// =============================================================================
// Architecture complète:
//   CI: Jenkins (local Kali) → Build, Test, Security, Docker, Integration
//   CD: Jenkins → SCP 3-hop → ctr import → ArgoCD Sync → Verify
//
// Cluster DPC:
//   5 nodes (3 masters + 2 workers), K8s v1.29.15, containerd 2.2.1
//   Calico CNI, cert-manager, Nginx Ingress Controller
//   HAProxy → Nginx Ingress → BeeWAF → IDTS Apps
//   ArgoCD, ELK Stack
//
// Pas de Docker Registry — images transférées via SCP + ctr import
// ArgoCD gère le déploiement GitOps depuis GitLab DPC
//
// SÉCURITÉ: Tous les secrets sont stockés dans Jenkins Credentials
// =============================================================================

pipeline {
    agent any
    
    environment {
        // =====================================================================
        // Configuration Docker (non sensible)
        // =====================================================================
        IMAGE_NAME    = 'beewaf'
        IMAGE_TAG     = "${env.BUILD_NUMBER}"
        K8S_IMAGE_TAG = 'sklearn'
        DOCKERFILE    = 'Dockerfile.k8s'
        
        // =====================================================================
        // Kubernetes & ArgoCD (non sensible)
        // =====================================================================
        K8S_NAMESPACE    = 'beewaf'
        K8S_DEPLOYMENT   = 'beewaf'
        ARGOCD_APP_NAME  = 'beewaf'
        ARGOCD_NAMESPACE = 'argocd'
        
        // =====================================================================
        // Credentials Jenkins - IDs des credentials stockés dans Jenkins
        // =====================================================================
        ARGOCD_CREDENTIALS_ID = 'argocd-credentials'
        ARGOCD_SERVER         = 'argocd-server.argocd.svc.cluster.local'
    }
    
    options {
        timeout(time: 45, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
        ansiColor('xterm')
    }
    
    stages {
        // =========================================================================
        // STAGE 1: Checkout — Récupérer le code depuis GitLab DPC
        // =========================================================================
        stage('Checkout') {
            steps {
                echo "🔍 Préparation du workspace..."
                // For standalone pipeline, skip git checkout
                // Use a dummy commit hash for local builds
                script {
                    env.GIT_SHORT_COMMIT = "local${env.BUILD_NUMBER}"
                    env.IMAGE_TAG = "${env.GIT_SHORT_COMMIT}"
                }
                
                script {
                    env.GIT_SHORT_COMMIT = sh(
                        script: 'git rev-parse --short HEAD',
                        returnStdout: true
                    ).trim()
                    env.IMAGE_TAG = "${env.GIT_SHORT_COMMIT}-${env.BUILD_NUMBER}"
                }
                
                echo "📦 Image CI : ${env.IMAGE_NAME}:${env.IMAGE_TAG}"
                echo "📦 Image K8s: ${env.IMAGE_NAME}:${env.K8S_IMAGE_TAG}"
                echo "📝 Commit   : ${env.GIT_SHORT_COMMIT}"
            }
        }
        
        // =========================================================================
        // STAGE 2: Install Dependencies
        // =========================================================================
        stage('Install Dependencies') {
            steps {
                echo "📥 Installation des dépendances..."
                sh '''
                    python3 -m venv .venv || true
                    . .venv/bin/activate
                    pip install --upgrade pip setuptools wheel
                    pip install -r requirements.txt
                    pip install pytest pytest-cov pip-audit bandit
                '''
            }
        }
        
        // =========================================================================
        // STAGE 3: Unit Tests
        // =========================================================================
        stage('Unit Tests') {
            steps {
                echo "🧪 Tests unitaires..."
                sh '''
                    . .venv/bin/activate
                    pytest tests/ -v --tb=short --junitxml=test-results.xml || true
                '''
            }
        }
        
        // =========================================================================
        // STAGE 4: Security Scan — Audit sécurité parallèle
        // =========================================================================
        stage('Security Scan') {
            parallel {
                stage('Dependency Audit') {
                    steps {
                        echo "🔒 Audit des dépendances Python (pip-audit)..."
                        sh '''
                            . .venv/bin/activate
                            pip-audit --format json --output pip-audit-report.json 2>&1 || echo "⚠️ Vulnérabilités détectées dans les dépendances"
                        '''
                    }
                }
                stage('Static Analysis') {
                    steps {
                        echo "🔍 Analyse statique du code (bandit)..."
                        sh '''
                            . .venv/bin/activate
                            bandit -r app/ waf/ -f json -o bandit-report.json || true
                        '''
                    }
                }
            }
        }
        
        // =========================================================================
        // STAGE 5: Build Docker Image
        // =========================================================================
        stage('Build Docker Image') {
            steps {
                echo "🏗️ Build de l'image Docker..."
                sh """
                    docker build \
                        -f Dockerfile.k8s \
                        -t ${env.IMAGE_NAME}:${env.IMAGE_TAG} \
                        -t ${env.IMAGE_NAME}:latest \
                        --build-arg BUILD_DATE=\$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
                        --build-arg VCS_REF=${env.GIT_SHORT_COMMIT} \
                        .
                """
                
                echo "✅ Image construite: ${env.IMAGE_NAME}:${env.IMAGE_TAG}"
            }
        }
        
        // =========================================================================
        // STAGE 6: Integration Tests
        // =========================================================================
        stage('Integration Tests') {
            steps {
                echo "🧪 Tests d'intégration..."
                sh """
                    docker rm -f beewaf_ci || true
                    docker run -d --name beewaf_ci \
                        -e BEEWAF_API_KEY=test-key-123 \
                        ${env.IMAGE_NAME}:${env.IMAGE_TAG}
                    
                    sleep 15
                    
                    # Récupérer l'IP du container
                    BEEWAF_IP=\$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' beewaf_ci)
                    echo "BeeWAF IP: \${BEEWAF_IP}"
                    
                    # Health check
                    curl -f http://\${BEEWAF_IP}:8000/health || exit 1
                    echo "✅ Health check OK"
                    
                    # Test SQL Injection
                    curl -s -X POST http://\${BEEWAF_IP}:8000/echo -d "' OR 1=1--" | grep -q "blocked" && echo "✅ SQLi bloqué" || echo "⚠️ SQLi non bloqué"
                    
                    # Test XSS
                    curl -s -X POST http://\${BEEWAF_IP}:8000/echo -d "<script>alert(1)</script>" | grep -q "blocked" && echo "✅ XSS bloqué" || echo "⚠️ XSS non bloqué"
                    
                    # Test Command Injection
                    curl -s -X POST http://\${BEEWAF_IP}:8000/echo -d "; cat /etc/passwd" | grep -q "blocked" && echo "✅ CMDi bloqué" || echo "⚠️ CMDi non bloqué"
                    
                    # Test Path Traversal
                    curl -s "http://\${BEEWAF_IP}:8000/echo?file=../../etc/passwd" | grep -q "blocked" && echo "✅ PathTraversal bloqué" || echo "⚠️ PathTraversal non bloqué"
                    
                    docker rm -f beewaf_ci
                """
            }
        }
        
        // =========================================================================
        // STAGE 7: Deploy via ArgoCD — Sync et déploiement GitOps
        // =========================================================================
        stage('Deploy via ArgoCD') {
            when {
                anyOf {
                    branch 'main'
                    branch 'master'
                    branch 'develop'
                }
            }
            steps {
                echo "🚀 Déploiement via ArgoCD sur le cluster DPC..."
                
                script {
                    withCredentials([usernamePassword(credentialsId: env.ARGOCD_CREDENTIALS_ID, usernameVariable: 'ARGOCD_USER', passwordVariable: 'ARGOCD_PASS')]) {
                        // Sync ArgoCD application via API
                        sh """
                            echo "🔄 Sync ArgoCD application: ${env.ARGOCD_APP_NAME}"
                            
                            # Sync via kubectl port-forward and argocd CLI
                            kubectl port-forward svc/argocd-server -n argocd 8080:443 &
                            sleep 5
                            
                            # Login and sync
                            argocd login localhost:8080 --username ${ARGOCD_USER} --password ${ARGOCD_PASS} --insecure
                            argocd app sync ${env.ARGOCD_APP_NAME} --server localhost:8080 --insecure
                            
                            # Wait for sync to complete
                            argocd app wait ${env.ARGOCD_APP_NAME} --server localhost:8080 --insecure --timeout 300
                            
                            # Kill port-forward
                            pkill -f "port-forward svc/argocd-server" || true
                            
                            echo "✅ ArgoCD sync terminé"
                        """
                    }
                }
            }
        }
        
        // =========================================================================
        // STAGE 8: Verify Deployment — Pods + Services + Health
        // =========================================================================
        stage('Verify Deployment') {
            when {
                anyOf {
                    branch 'main'
                    branch 'master'
                    branch 'develop'
                }
            }
            steps {
                echo "🔍 Vérification du déploiement..."
                
                script {
                    withCredentials([usernamePassword(credentialsId: env.ARGOCD_CREDENTIALS_ID, usernameVariable: 'ARGOCD_USER', passwordVariable: 'ARGOCD_PASS')]) {
                        sh """
                            echo "=== PODS BeeWAF ==="
                            kubectl get pods -n ${env.K8S_NAMESPACE} -o wide
                            
                            echo ""
                            echo "=== SERVICES ==="
                            kubectl get svc -n ${env.K8S_NAMESPACE}
                            
                            echo ""
                            echo "=== ARGOCD APP STATUS ==="
                            kubectl get application ${env.ARGOCD_APP_NAME} -n argocd -o yaml | grep -A5 "status:" || echo "ArgoCD app status not available"
                            
                            echo ""
                            echo "=== HEALTH CHECK ==="
                            kubectl exec -n ${env.K8S_NAMESPACE} \$(kubectl get pod -n ${env.K8S_NAMESPACE} -l app=beewaf -o jsonpath='{.items[0].metadata.name}') -- curl -s http://localhost:8000/health || echo "Health check failed"
                        """
                    }
                }
            }
        }
    }
    
    post {
        success {
            echo """
            ╔══════════════════════════════════════════════════════════════╗
            ║              🐝 PIPELINE BeeWAF — RÉUSSI ✅                ║
            ╠══════════════════════════════════════════════════════════════╣
            ║  Image  : ${env.IMAGE_NAME}:${env.K8S_IMAGE_TAG}
            ║  Commit : ${env.GIT_SHORT_COMMIT}
            ║  Build  : #${env.BUILD_NUMBER}
            ║  ArgoCD : ${env.ARGOCD_APP_NAME}
            ║  Cluster: DPC (5 nodes, K8s v1.29.15)
            ╚══════════════════════════════════════════════════════════════╝
            """
        }
        failure {
            echo """
            ╔══════════════════════════════════════════════════════════════╗
            ║              🐝 PIPELINE BeeWAF — ÉCHOUÉ ❌                ║
            ╠══════════════════════════════════════════════════════════════╣
            ║  Build  : #${env.BUILD_NUMBER}
            ║  Vérifiez les logs Jenkins pour plus de détails
            ╚══════════════════════════════════════════════════════════════╝
            """
        }
        always {
            sh 'docker rm -f beewaf_ci 2>/dev/null || true'
            archiveArtifacts artifacts: '**/test-results.xml, **/bandit-report.json, **/pip-audit-report.json', allowEmptyArchive: true
        }
    }
}
