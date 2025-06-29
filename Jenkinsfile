pipeline {
    agent any

    stages {
        stage('Clone Repository') {
            steps {
                git 'https://github.com/hurihidayat12/scanerdey'  // ganti dengan repo kamu
            }
        }

        stage('Scan CVE') {
            steps {
                sh 'docker run --rm -v $(pwd):/app aquasec/trivy fs /app > hasil-scan.txt'
            }
        }

        stage('Report CVSS') {
            steps {
                archiveArtifacts artifacts: 'hasil-scan.txt', onlyIfSuccessful: true
            }
        }
        stage('Parse CVSS') {
            steps {
                sh 'python3 parser.py'
    }
}
    }
}
