import { useState } from "react";
import axios from "axios";
import { Pie } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import { FaShieldAlt, FaCookieBite, FaExclamationTriangle } from "react-icons/fa";
ChartJS.register(ArcElement, Tooltip, Legend);

function Dashboard() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!url.trim()) {
      setError("Please enter a URL.");
      return;
    }

    setLoading(true);
    setError("");
    setReport(null);

    try {
      const vulnResponse = await axios.post("http://127.0.0.1:5000/api/vuln-scan", { url });
      const cookieResponse = await axios.post("http://127.0.0.1:5000/api/cookie-scan", { url });
      const phishingResponse = await axios.post("http://127.0.0.1:5000/api/phishing-check", { url });

      setReport({
        vulnerability: vulnResponse.data,
        cookies: cookieResponse.data,
        phishing: phishingResponse.data
      });
    } catch (err) {
      setError("Backend error. Make sure the Python server is running.");
    }

    setLoading(false);
  };

  const issues = report?.vulnerability?.issues_found || [];
  const issueWeights = {
    "Missing: Content-Security-Policy": 30,
    "Missing: X-Frame-Options": 20,
    "Missing: Strict-Transport-Security": 25,
    "Missing: X-Content-Type-Options": 25,
    "Non-200 Status Code": 25,
    "No major vulnerabilities detected ✔": 0,
    "Website could not be scanned — unreachable.": 0
  };

  let overallScore = 100 - issues.reduce((sum, i) => sum + (issueWeights[i] || 10), 0);
  overallScore = Math.max(0, overallScore);

  const chartData = {
    labels: issues.length > 0 ? issues : ["No issues"],
    datasets: [
      {
        data: issues.length > 0 ? issues.map(i => issueWeights[i] || 10) : [100],
        backgroundColor: ["#FF6384", "#36A2EB", "#FFCE56", "#4BC0C0", "#9966FF"],
        borderWidth: 1,
      },
    ],
  };

  const chartOptions = {
    plugins: {
      legend: { position: 'bottom', labels: { font: { size: 14 } } },
      tooltip: {
        callbacks: {
          label: function(context) {
            return `${context.label}: ${context.parsed} pts`;
          }
        }
      }
    }
  };

  return (
    <div style={{
      padding: "40px",
      fontFamily: "'Poppins', sans-serif",
      minHeight: "100vh",
      background: "linear-gradient(135deg, #f0f4ff, #e0f7fa)"
    }}>
      {/* Header */}
      <div style={{
        textAlign: 'center',
        padding: '25px',
        borderRadius: '12px',
        background: 'linear-gradient(90deg, #2a66ff, #36d1dc)',
        color: '#fff',
        marginBottom: '30px',
        boxShadow: '0 6px 20px rgba(0,0,0,0.1)'
      }}>
        <h1 style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '10px' }}>
          <FaShieldAlt /> SecGap Security Analyzer
        </h1>
      </div>

      {/* URL Input */}
      <div style={{ maxWidth: "600px", margin: "0 auto 20px auto" }}>
        <input
          type="text"
          placeholder="Enter website URL (https://example.com)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{
            width: "100%",
            padding: "14px",
            marginBottom: "10px",
            borderRadius: "10px",
            border: "1px solid #ccc",
            fontSize: "16px",
          }}
        />
        <button
          onClick={handleScan}
          style={{
            width: "100%",
            padding: "14px",
            fontSize: "16px",
            background: "#2a66ff",
            color: "white",
            border: "none",
            borderRadius: "10px",
            cursor: "pointer",
            transition: "all 0.3s ease"
          }}
          onMouseEnter={e => e.currentTarget.style.background = "#184bd1"}
          onMouseLeave={e => e.currentTarget.style.background = "#2a66ff"}
        >
          {loading ? "Scanning..." : "Scan Security"}
        </button>
        {error && <p style={{ color: "red", textAlign: "center", marginTop: "10px" }}>{error}</p>}
      </div>

      {/* Report Sections */}
      {report && (
        <div style={{ maxWidth: "900px", margin: "0 auto" }}>

          {/* Vulnerability Scan */}
          <div className="card">
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <FaShieldAlt /> Vulnerability Scan
            </h2>
            <p><strong>Overall Score:</strong> {overallScore} / 100</p>
            {issues.length > 0 && (
              <div style={{ maxWidth: "400px", margin: "20px auto" }}>
                <Pie data={chartData} options={chartOptions} />
              </div>
            )}
            <ul>
              {issues.map((issue, index) => <li key={index}><strong>{issue}</strong></li>)}
              {issues.length === 0 && <li>No vulnerabilities found ✓</li>}
            </ul>
          </div>

          {/* Cookie Analyzer */}
          <div className="card">
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <FaCookieBite /> Cookie Analyzer
            </h2>
            <ul>
              {report.cookies.cookies.map((cookie, index) => {
                if (cookie.cookie) {
                  const flags = [];
                  if (cookie.cookie.toLowerCase().includes("secure")) flags.push("HTTPS only");
                  if (cookie.cookie.toLowerCase().includes("httponly")) flags.push("Not accessible to JS");
                  if (cookie.cookie.toLowerCase().includes("samesite")) flags.push("SameSite set");
                  return <li key={index}>{cookie.cookie} - {flags.join(", ")}</li>
                } else {
                  return <li key={index}>{cookie.info || cookie.error}</li>
                }
              })}
            </ul>
          </div>

          {/* Phishing Check */}
          <div className="card">
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <FaExclamationTriangle /> Phishing Check
            </h2>
            <p><strong>Suspicious:</strong> {report.phishing.suspicious ? "Yes ❌" : "No ✅"}</p>
            <ul>
              {report.phishing.reasons.length > 0 ? report.phishing.reasons.map((r, i) => <li key={i}>{r}</li>) : <li>No suspicious patterns detected ✓</li>}
            </ul>
          </div>

        </div>
      )}
    </div>
  );
}

export default Dashboard;
