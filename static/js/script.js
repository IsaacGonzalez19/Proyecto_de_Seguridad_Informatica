document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('emailForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const results = document.getElementById('results');
    const resultsHeader = document.getElementById('resultsHeader');
    const resultsBody = document.getElementById('resultsBody');

    form.addEventListener('submit', function(e) {
        e.preventDefault();
        analyzeEmail();
    });

    async function analyzeEmail() {
        const emailContent = document.getElementById('emailContent').value.trim();

        if (!emailContent) {
            alert('Por favor, ingresa el contenido del correo electrónico');
            return;
        }

        // Mostrar estado de carga
        analyzeBtn.innerHTML = '⏳ Analizando...';
        analyzeBtn.disabled = true;
        results.style.display = 'none';

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email_content: emailContent
                })
            });

            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            displayResults(data.analysis);

        } catch (error) {
            console.error('Error:', error);
            alert('Error al analizar el correo: ' + error.message);
        } finally {
            analyzeBtn.innerHTML = '🔍 Analizar Correo';
            analyzeBtn.disabled = false;
        }
    }

    function displayResults(analysis) {
        const { risk_level, risk_color, score, detected_keywords, suspicious_urls, total_urls } = analysis;

        // Configurar header según el nivel de riesgo
        resultsHeader.className = `card-header bg-${risk_color} text-white`;

        let alertClass;
        let riskIcon;
        let recommendation;

        switch (risk_level) {
            case 'ALTO':
                alertClass = 'alert-danger';
                riskIcon = '🚨';
                recommendation = 'NO interactúes con este correo. Es muy probable que sea phishing.';
                break;
            case 'MEDIO':
                alertClass = 'alert-warning';
                riskIcon = '⚠️';
                recommendation = 'Ten precaución. Verifica la fuente antes de realizar cualquier acción.';
                break;
            default:
                alertClass = 'alert-success';
                riskIcon = '✅';
                recommendation = 'El correo parece seguro, pero siempre mantén precaución.';
        }

        resultsBody.innerHTML = `
            <div class="alert ${alertClass} risk-${risk_level.toLowerCase()}" role="alert">
                <h4 class="alert-heading">${riskIcon} Nivel de Riesgo: ${risk_level}</h4>
                <p><strong>Puntuación de riesgo:</strong> ${score} puntos</p>
                <hr>
                <p class="mb-0"><strong>Recomendación:</strong> ${recommendation}</p>
            </div>

            ${detected_keywords.length > 0 ? `
                <div class="mt-3">
                    <h6>🔍 Palabras clave sospechosas detectadas:</h6>
                    <div class="d-flex flex-wrap gap-2">
                        ${detected_keywords.map(keyword => `
                            <span class="badge bg-warning text-dark">${keyword}</span>
                        `).join('')}
                    </div>
                </div>
            ` : ''}

            ${suspicious_urls.length > 0 ? `
                <div class="mt-3">
                    <h6>🔗 URLs sospechosas encontradas:</h6>
                    <ul class="list-group">
                        ${suspicious_urls.map(url => `
                            <li class="list-group-item list-group-item-warning">
                                <code>${url}</code>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            ` : ''}

            <div class="mt-3">
                <small class="text-muted">
                    📈 Total de URLs encontradas: ${total_urls} | 
                    🛡️ Análisis realizado con éxito
                </small>
            </div>
        `;

        results.style.display = 'block';
        results.scrollIntoView({ behavior: 'smooth' });
    }
});