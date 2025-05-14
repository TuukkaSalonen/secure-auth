Jenkins pipeline script

Requires Docker, Trivy and Python installed on the system.
Also Dependency-Check, Node and Java JDK are needed to be installed in Jenkins plugins.

pipeline {
    agent any
    tools {
        jdk 'jdk17'
        nodejs 'node20'
    }
    environment {
        SCANNER_HOME = tool 'sonar-scanner'
        NVD_KEY = credentials('NVD')
    }
    stages {
        stage('Check Python') {
            steps {
                sh 'python3 --version'
            }
        }
        stage('Clean Workspace') {
            steps {
                cleanWs()
            }
        }
        stage('Checkout from Git') {
            steps {
                git branch: 'main', url: 'https://github.com/TuukkaSalonen/secure-auth.git'
            }
        }
        stage('Setup Python Virtual Environment') {
            steps {
                sh "python3 -m venv venv"
                sh "./venv/bin/pip install --upgrade pip"
                sh "./venv/bin/pip install semgrep"
            }
        }
        stage('SAST - Semgrep') {
            steps {
                sh "./venv/bin/semgrep scan --config=auto --json > semgrep-report.json"
            }
        }
        stage('Install Backend Dependencies') {
            steps {
                dir('backend') {
                    sh "python3 -m venv venv"
                    sh ". venv/bin/activate && pip install -r requirements.txt"
                }
            }
        }
        stage('Install Frontend Dependencies') {
            steps {
                dir('frontend') {
                    sh "npm install"
                    sh "npm install --save-dev @cyclonedx/cyclonedx-npm"
                    sh "npx cyclonedx-npm --output-file sbom.json"
                }
            }
        }
        stage('SCA - Dependency Check') {
            steps {
                dependencyCheck additionalArguments: '--scan ./ --disableYarnAudit --disableNodeAudit --nvdApiKey=$NVD_KEY --enableExperimental', odcInstallation: 'DP-Check'
                dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
            }
        }
        stage('File System Scan - Trivy') {
            steps {
                sh "trivy fs -f json -o trivy_system.json ."
            }
        }
        stage('Run Backend') {
            steps {
                dir('backend') {
                    sh ". venv/bin/activate && python run.py &"
                }
            }
        }
        stage('Run Frontend') {
            steps {
                dir('frontend') {
                      sh '''
                echo "Starting frontend..."
                npm run dev -- --host 0.0.0.0 &
            '''
        }
                }
            }
        stage('DAST - OWASP ZAP') {
            steps {
                sh '''
                    mkdir -p zap-wrk
                    chmod 777 zap-wrk
            
                    docker run --rm --network=host -v "$(pwd)/zap-wrk:/zap/wrk" zaproxy/zap-stable zap-baseline.py -t http://localhost:5173/ -r DAST_Report.html -a -I
                '''
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: '**/dependency-check-report.xml, frontend/sbom.json, semgrep-report.json, trivy_system.json, zap-wrk/DAST_Report.html', allowEmptyArchive: true
        }
    }
}