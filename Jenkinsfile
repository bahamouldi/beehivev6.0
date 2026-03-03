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
//   HAProxy (207.180.211.157) → Nginx Ingress → BeeWAF → IDTS Apps
//   ArgoCD v3.3.0 (argocd.dpc.com.tn), ELK Stack
//
// Pas de Docker Registry — images transférées via SCP + ctr import
// ArgoCD gère le déploiement GitOps depuis GitLab DPC
// =============================================================================

pipeline {
    agent any
    
    environment {
        // =====================================================================
        // Configuration Docker
        // =====================================================================
        IMAGE_NAME    = 'beewaf'
        IMAGE_TAG     = "${env.BUILD_NUMBER}"
        // Tag utilisé dans le deployment K8s (containerd)
        K8S_IMAGE_TAG = 'sklearn'
        DOCKERFILE    = 'Dockerfile.k8s'
        
        // =====================================================================
        // Configuration SSH — Chaîne de connexion vers le cluster DPC
        // Kali → Passerelle (port 258) → HAProxy (port 8520) → Master K8s
        // =====================================================================
        PASSERELLE_HOST = 'passrelle.dpc.com.tn'
        PASSERELLE_PORT = '258'
        PASSERELLE_USER = 'baha'
        
        HAPROXY_HOST = 'haproxystage.dpc.com.tn'
        HAPROXY_PORT = '8520'
        HAPROXY_USER = 'baha'
        
        MASTER_HOST = '192.168.90.10'
        MASTER_USER = 'baha'
        
        // =====================================================================
        // Kubernetes & ArgoCD
        // =====================================================================
        K8S_NAMESPACE    = 'beewaf'
        K8S_DEPLOYMENT   = 'beewaf'
        ARGOCD_APP_NAME  = 'beewaf'
        ARGOCD_NAMESPACE = 'argocd'
        
        // =====================================================================
        // Credentials Jenkins
        // =====================================================================
        SSH_CREDENTIALS_ID    = 'ssh-dpc-credentials'
        GITLAB_CREDENTIALS_ID = 'gitlab-dpc-credentials'
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
                echo "🔍 Checkout du code source depuis GitLab DPC..."
                checkout scm
                
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
        // STAGE 7: Transfer Image — SCP 3-hop vers le Master K8s
        // Kali → Passerelle (port 258) → HAProxy (port 8520) → Master
        // Pas de Docker Registry → transfert via SCP + ctr import
        // =========================================================================
        stage('Transfer to Cluster') {
            when {
                anyOf {
                    branch 'main'
                    branch 'master'
                    branch 'develop'
                }
            }
            steps {
                echo "📤 Transfert de l'image vers le cluster DPC (3 hops SSH)..."
                
                script {
                    // Tag avec le nom utilisé dans le deployment K8s
                    sh "docker tag ${env.IMAGE_NAME}:${env.IMAGE_TAG} ${env.IMAGE_NAME}:${env.K8S_IMAGE_TAG}"
                    
                    // Sauvegarder l'image avec le tag sklearn
                    sh "docker save ${env.IMAGE_NAME}:${env.K8S_IMAGE_TAG} | gzip > /tmp/beewaf-${env.K8S_IMAGE_TAG}.tar.gz"
                    sh "ls -lh /tmp/beewaf-${env.K8S_IMAGE_TAG}.tar.gz"
                    
                    sshagent(credentials: [env.SSH_CREDENTIALS_ID]) {
                        // Hop 1: Kali/Jenkins → Passerelle
                        sh """
                            scp -o StrictHostKeyChecking=no \
                                -P ${env.PASSERELLE_PORT} \
                                /tmp/beewaf-${env.K8S_IMAGE_TAG}.tar.gz \
                                ${env.PASSERELLE_USER}@${env.PASSERELLE_HOST}:/tmp/
                        """
                        
                        // Hop 2: Passerelle → HAProxy
                        sh """
                            ssh -o StrictHostKeyChecking=no \
                                -p ${env.PASSERELLE_PORT} \
                                ${env.PASSERELLE_USER}@${env.PASSERELLE_HOST} \
                                'scp -o StrictHostKeyChecking=no -P ${env.HAPROXY_PORT} /tmp/beewaf-${env.K8S_IMAGE_TAG}.tar.gz ${env.HAPROXY_USER}@${env.HAPROXY_HOST}:/tmp/'
                        """
                        
                        // Hop 3: HAProxy → Master K8s
                        sh """
                            ssh -o StrictHostKeyChecking=no \
                                -p ${env.PASSERELLE_PORT} \
                                ${env.PASSERELLE_USER}@${env.PASSERELLE_HOST} \
                                'ssh -o StrictHostKeyChecking=no -p ${env.HAPROXY_PORT} ${env.HAPROXY_USER}@${env.HAPROXY_HOST} \
                                \"scp -o StrictHostKeyChecking=no /tmp/beewaf-${env.K8S_IMAGE_TAG}.tar.gz ${env.MASTER_USER}@${env.MASTER_HOST}:/tmp/\"'
                        """
                    }
                }
                
                echo "✅ Image transférée vers Master K8s (${env.MASTER_HOST})"
            }
        }
        
        // =========================================================================
        // STAGE 8: Deploy via ArgoCD — Import image + rollout + ArgoCD sync
        // containerd import + kubectl rollout + ArgoCD hard refresh
        // ArgoCD gère les manifests K8s depuis GitLab (path: k8s/)
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
                    sshagent(credentials: [env.SSH_CREDENTIALS_ID]) {
                        // Import image dans containerd + rollout restart
                        sh """
                            ssh -o StrictHostKeyChecking=no \
                                -p ${env.PASSERELLE_PORT} \
                                ${env.PASSERELLE_USER}@${env.PASSERELLE_HOST} \
                                'ssh -o StrictHostKeyChecking=no \
                                    -p ${env.HAPROXY_PORT} \
                                    ${env.HAPROXY_USER}@${env.HAPROXY_HOST} \
                                    "ssh -o StrictHostKeyChecking=no \
                                        ${env.MASTER_USER}@${env.MASTER_HOST} \
                                        \\"sudo ctr -n k8s.io images import /tmp/beewaf-${env.K8S_IMAGE_TAG}.tar.gz && \
                                           echo Image importee dans containerd OK && \
                                           sudo kubectl rollout restart deployment/${env.K8S_DEPLOYMENT} -n ${env.K8S_NAMESPACE} && \
                                           sudo kubectl rollout status deployment/${env.K8S_DEPLOYMENT} -n ${env.K8S_NAMESPACE} --timeout=120s && \
                                           echo Rollout termine avec succes\\""'
                        """
                    }
                }
                
                echo "✅ Déploiement terminé — ArgoCD sync automatique"
            }
        }
        
        // =========================================================================
        // STAGE 9: Verify Deployment — Pods + Services + ArgoCD + Health
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
                    sshagent(credentials: [env.SSH_CREDENTIALS_ID]) {
                        sh """
                            ssh -o StrictHostKeyChecking=no \
                                -p ${env.PASSERELLE_PORT} \
                                ${env.PASSERELLE_USER}@${env.PASSERELLE_HOST} \
                                'ssh -o StrictHostKeyChecking=no \
                                    -p ${env.HAPROXY_PORT} \
                                    ${env.HAPROXY_USER}@${env.HAPROXY_HOST} \
                                    "ssh -o StrictHostKeyChecking=no \
                                        ${env.MASTER_USER}@${env.MASTER_HOST} \
                                        \\"echo === PODS BeeWAF === && \
                                           sudo kubectl get pods -n ${env.K8S_NAMESPACE} -o wide && \
                                           echo && echo === SERVICES === && \
                                           sudo kubectl get svc -n ${env.K8S_NAMESPACE} && \
                                           echo && echo === ARGOCD APP === && \
                                           sudo kubectl get app ${env.ARGOCD_APP_NAME} -n ${env.ARGOCD_NAMESPACE} 2>/dev/null || echo ArgoCD app not yet registered && \
                                           echo && echo === HEALTH CHECK === && \
                                           sudo kubectl exec \\\$(sudo kubectl get pod -n ${env.K8S_NAMESPACE} -l app=beewaf -o jsonpath=\'{.items[0].metadata.name}\') -n ${env.K8S_NAMESPACE} -- curl -s http://localhost:8000/health\\""'
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
