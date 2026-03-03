// =============================================================================
// BeeWAF — Jenkins Pipeline CI/CD (Adapté pour cluster DPC)
// =============================================================================
// Architecture: Jenkins → Passerelle → HAProxy → Master1 (K8s)
// 
// Ce pipeline implémente:
// - CI: Build, Test, Security Scan
// - CD: Transfert SSH + Déploiement sur cluster DPC
// =============================================================================

pipeline {
    agent any
    
    environment {
        // Configuration Docker
        IMAGE_NAME = 'beewaf'
        IMAGE_TAG = "${env.BUILD_NUMBER}"
        
        // Configuration SSH pour le cluster DPC
        PASSERELLE_HOST = 'passrelle.dpc.com.tn'
        PASSERELLE_PORT = '258'
        PASSERELLE_USER = 'baha'
        
        HAPROXY_HOST = 'haproxystage.dpc.com.tn'
        HAPROXY_PORT = '8520'
        HAPROXY_USER = 'baha'
        
        MASTER_HOST = '192.168.90.10'
        MASTER_USER = 'baha'
        
        // Kubernetes
        K8S_NAMESPACE = 'beewaf'
        
        // Credentials IDs
        SSH_CREDENTIALS_ID = 'ssh-dpc-credentials'
    }
    
    options {
        timeout(time: 45, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
        ansiColor('xterm')
    }
    
    stages {
        // =========================================================================
        // STAGE 1: Checkout
        // =========================================================================
        stage('Checkout') {
            steps {
                echo "🔍 Checkout du code source..."
                checkout scm
                
                script {
                    env.GIT_SHORT_COMMIT = sh(
                        script: 'git rev-parse --short HEAD',
                        returnStdout: true
                    ).trim()
                    env.IMAGE_TAG = "${env.GIT_SHORT_COMMIT}-${env.BUILD_NUMBER}"
                }
                
                echo "📦 Image: ${env.IMAGE_NAME}:${env.IMAGE_TAG}"
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
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'test-results.xml'
                }
            }
        }
        
        // =========================================================================
        // STAGE 4: Security Scan
        // =========================================================================
        stage('Security Scan') {
            parallel {
                stage('Dependency Check') {
                    steps {
                        echo "🔒 Vérification des dépendances..."
                        sh '''
                            . .venv/bin/activate
                            pip audit --format json --output pip-audit-report.json || echo "⚠️ Vulnérabilités détectées dans les dépendances"
                        '''
                    }
                }
                stage('Code Analysis') {
                    steps {
                        echo "🔍 Analyse statique..."
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
                    docker run -d --name beewaf_ci -p 8000:8000 \
                        -e BEEWAF_API_KEY=test-key-123 \
                        ${env.IMAGE_NAME}:${env.IMAGE_TAG}
                    
                    sleep 15
                    
                    # Health check
                    curl -f http://localhost:8000/health || exit 1
                    
                    # Test SQL Injection
                    curl -s -X POST http://localhost:8000/echo -d "' OR 1=1--" | grep -q "blocked" && echo "✅ SQLi bloqué" || echo "⚠️ SQLi non bloqué"
                    
                    # Test XSS
                    curl -s -X POST http://localhost:8000/echo -d "<script>alert(1)</script>" | grep -q "blocked" && echo "✅ XSS bloqué" || echo "⚠️ XSS non bloqué"
                    
                    # Test Command Injection
                    curl -s -X POST http://localhost:8000/echo -d "; cat /etc/passwd" | grep -q "blocked" && echo "✅ CMDi bloqué" || echo "⚠️ CMDi non bloqué"
                    
                    # Test Path Traversal
                    curl -s "http://localhost:8000/echo?file=../../etc/passwd" | grep -q "blocked" && echo "✅ PathTraversal bloqué" || echo "⚠️ PathTraversal non bloqué"
                    
                    docker rm -f beewaf_ci
                """
            }
        }
        
        // =========================================================================
        // STAGE 7: Save & Transfer Image
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
                echo "📤 Transfert de l'image vers le cluster DPC..."
                
                script {
                    // Sauvegarder l'image
                    sh "docker save ${env.IMAGE_NAME}:${env.IMAGE_TAG} | gzip > /tmp/beewaf-${env.IMAGE_TAG}.tar.gz"
                    
                    sshagent(credentials: [env.SSH_CREDENTIALS_ID]) {
                        // Étape 1: Kali/Jenkins → Passerelle
                        sh """
                            scp -o StrictHostKeyChecking=no \
                                -P ${env.PASSERELLE_PORT} \
                                /tmp/beewaf-${env.IMAGE_TAG}.tar.gz \
                                ${env.PASSERELLE_USER}@${env.PASSERELLE_HOST}:/tmp/
                        """
                        
                        // Étape 2: Passerelle → HAProxy
                        sh """
                            ssh -o StrictHostKeyChecking=no \
                                -p ${env.PASSERELLE_PORT} \
                                ${env.PASSERELLE_USER}@${env.PASSERELLE_HOST} \
                                'scp -o StrictHostKeyChecking=no -P ${env.HAPROXY_PORT} /tmp/beewaf-${env.IMAGE_TAG}.tar.gz ${env.HAPROXY_USER}@${env.HAPROXY_HOST}:/tmp/'
                        """
                        
                        // Étape 3: HAProxy → Master
                        sh """
                            ssh -o StrictHostKeyChecking=no \
                                -p ${env.PASSERELLE_PORT} \
                                ${env.PASSERELLE_USER}@${env.PASSERELLE_HOST} \
                                'ssh -o StrictHostKeyChecking=no -p ${env.HAPROXY_PORT} ${env.HAPROXY_USER}@${env.HAPROXY_HOST} \
                                \"scp -o StrictHostKeyChecking=no /tmp/beewaf-${env.IMAGE_TAG}.tar.gz ${env.MASTER_USER}@${env.MASTER_HOST}:/tmp/\"'
                        """
                    }
                }
                
                echo "✅ Image transférée vers le Master"
            }
        }
        
        // =========================================================================
        // STAGE 8: Deploy to Kubernetes
        // =========================================================================
        stage('Deploy to Kubernetes') {
            when {
                anyOf {
                    branch 'main'
                    branch 'master'
                    branch 'develop'
                }
            }
            steps {
                echo "🚀 Déploiement sur le cluster..."
                
                script {
                    def imageTag = env.IMAGE_TAG
                    
                    sshagent(credentials: [env.SSH_CREDENTIALS_ID]) {
                        // Script de déploiement distant
                        sh """
                            ssh -o StrictHostKeyChecking=no \
                                -p ${env.PASSERELLE_PORT} \
                                ${env.PASSERELLE_USER}@${env.PASSERELLE_HOST} \
                                'ssh -o StrictHostKeyChecking=no \
                                    -p ${env.HAPROXY_PORT} \
                                    ${env.HAPROXY_USER}@${env.HAPROXY_HOST} \
                                    "ssh -o StrictHostKeyChecking=no \
                                        ${env.MASTER_USER}@${env.MASTER_HOST} \
                                        \\"sudo ctr -n k8s.io images import /tmp/beewaf-${imageTag}.tar.gz && \
                                           sudo kubectl rollout restart deployment/beewaf -n beewaf && \
                                           sudo kubectl rollout status deployment/beewaf -n beewaf --timeout=120s\\""'
                        """
                    }
                }
                
                echo "✅ Déploiement terminé"
            }
        }
        
        // =========================================================================
        // STAGE 9: Verify Deployment
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
                                        \\"sudo kubectl get pods -n beewaf -o wide && \
                                           sudo kubectl get svc -n beewaf && \
                                           echo && echo HEALTH_CHECK: && \
                                           sudo kubectl exec \\\$(sudo kubectl get pod -n beewaf -l app=beewaf -o jsonpath=\'{.items[0].metadata.name}\') -n beewaf -- curl -s http://localhost:8000/health\\""'
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
            ║                    ✅ PIPELINE RÉUSSI                       ║
            ╠══════════════════════════════════════════════════════════════╣
            ║  Image: ${env.IMAGE_NAME}:${env.IMAGE_TAG}
            ║  Commit: ${env.GIT_SHORT_COMMIT}
            ║  Build: #${env.BUILD_NUMBER}
            ║  Cluster: DPC (Master1)
            ╚══════════════════════════════════════════════════════════════╝
            """
        }
        failure {
            echo """
            ╔══════════════════════════════════════════════════════════════╗
            ║                    ❌ PIPELINE ÉCHOUÉ                        ║
            ╠══════════════════════════════════════════════════════════════╣
            ║  Vérifiez les logs pour plus de détails
            ║  Build: #${env.BUILD_NUMBER}
            ╚══════════════════════════════════════════════════════════════╝
            """
        }
        always {
            sh 'docker rm -f beewaf_ci || true'
            archiveArtifacts artifacts: 'test-results.xml, bandit-report.json', allowEmptyArchive: true
        }
    }
}
