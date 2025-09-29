pipeline {
  agent {
    docker {
      image 'docker:25.0.3-cli'
      args '-v /var/run/docker.sock:/var/run/docker.sock --entrypoint=""'
      reuseNode true
    }
  }

  options { skipDefaultCheckout(true); timestamps() }

  environment {
    REPORT_DIR        = "security-reports"
    // ให้ Semgrep drop ตั้งแต่ WARNING ขึ้นไป
    SEMGREP_FAIL_ON   = "WARNING"
    // ให้ Trivy drop ตั้งแต่ LOW ขึ้นไปทั้งหมด
    TRIVY_FAIL_ON     = "LOW,MEDIUM,HIGH,CRITICAL"
    DEMO_FAIL         = "false"
    JENKINS_CONTAINER = "jenkins"
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
        sh 'mkdir -p "$REPORT_DIR"'
      }
    }

    stage('Semgrep (OWASP, strict)') {
      steps {
        sh '''
          set -e
          docker run --rm \
            --volumes-from "${JENKINS_CONTAINER}" \
            -w "$WORKSPACE" \
            python:3.11-slim bash -lc "
              apt-get update -qq && apt-get install -y -qq git >/dev/null &&
              pip install --no-cache-dir -q semgrep &&
              # ใช้ --no-git + include ให้กวาดไฟล์ .py ทั้งหมด แม้ repo จะไม่มี git metadata ใน container
              semgrep \
                --config=p/owasp-top-ten \
                --config=p/python \
                --no-git --include '**/*.py' \
                --severity \\"${SEMGREP_FAIL_ON}\\" \
                --sarif --output ${REPORT_DIR}/semgrep.sarif \
                --error
            "
        '''
      }
    }

    stage('Bandit (Python SAST) - strict (ไม่เป็น gate)') {
      steps {
        sh '''
          docker run --rm \
            --volumes-from "${JENKINS_CONTAINER}" \
            -w "$WORKSPACE" \
            python:3.11-slim bash -lc "
              pip install --no-cache-dir -q bandit==1.* &&
              # ระดับ -ll (medium/high) เก็บรายงานไว้ดู แต่ไม่ทำให้ล้ม
              bandit -r . -ll -f json -o ${REPORT_DIR}/bandit.json || true
            "
        '''
      }
    }

    stage('pip-audit (Dependencies) - strict (ไม่เป็น gate)') {
      steps {
        sh '''
          docker run --rm \
            --volumes-from "${JENKINS_CONTAINER}" \
            -w "$WORKSPACE" \
            python:3.11-slim bash -lc "
              set -e
              pip install --no-cache-dir -q pip-audit
              shopt -s nullglob
              files=(requirements*.txt)
              if [ \\${#files[@]} -eq 0 ]; then
                echo 'No requirements*.txt found, skipping pip-audit.'; exit 0
              fi
              for f in \\"\\${files[@]}\\"; do
                echo Running pip-audit on \\"$f\\"
                pip-audit -r \\"$f\\" -f json -o \\"${REPORT_DIR}/pip-audit_$(basename \\"$f\\" .txt).json\\" || true
              done
            "
        '''
      }
    }

    stage('Trivy FS (vuln/misconfig/secret) - strict') {
      steps {
        sh '''
          set +e
          docker run --rm \
            --volumes-from "${JENKINS_CONTAINER}" \
            -w "$WORKSPACE" \
            aquasec/trivy:latest fs . \
              --scanners vuln,misconfig,secret \
              --severity ${TRIVY_FAIL_ON} \
              --format sarif --output ${REPORT_DIR}/trivy.sarif \
              --exit-code 1
          TRIVY_RC=$?
          set -e
          # ถ้าต้องการบังคับให้ fail ไม่ว่าอย่างไร ให้ปล่อย TRIVY_RC ใช้ค่าเดิม
          if [ "${TRIVY_RC}" -ne 0 ]; then
            echo "Trivy found findings at ${TRIVY_FAIL_ON}."; exit 1
          fi
        '''
      }
    }

    stage('Publish Reports') {
      steps {
        recordIssues(enabledForFailure: true, tools: [sarif(pattern: "${REPORT_DIR}/*.sarif")])
        archiveArtifacts artifacts: "${REPORT_DIR}/**", allowEmptyArchive: true
      }
    }

    stage('Force Failure (Demo)') {
      steps {
        sh '''
          if [ "${DEMO_FAIL}" = "true" ]; then
            echo "Forcing FAILURE for demo purpose (set DEMO_FAIL=false to disable)."
            exit 1
          else
            echo "DEMO_FAIL=false -> not forcing failure."
          fi
        '''
      }
    }
  }

  post {
    always  { echo "Scan completed. Reports archived in ${REPORT_DIR}/" }
    failure { echo "Build failed (strict demo). See Warnings and artifacts for details." }
    success { echo "Build succeeded (you probably set DEMO_FAIL=false or no strict findings were hit)." }
  }
}
