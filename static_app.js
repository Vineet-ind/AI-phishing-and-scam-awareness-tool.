const messageInput = document.querySelector("#message");
const analyzeButton = document.querySelector("#analyze");
const resultPanel = document.querySelector("#result");
const toast = document.querySelector("#toast");

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

messageInput.addEventListener("input", () => {
  document.querySelector("#char-count").textContent = `${messageInput.value.length.toLocaleString()} / 10,000`;
});

document.querySelectorAll(".example").forEach((button) => {
  button.addEventListener("click", () => {
    messageInput.value = button.dataset.example;
    messageInput.dispatchEvent(new Event("input"));
    messageInput.focus();
  });
});

document.querySelector("#clear").addEventListener("click", () => {
  messageInput.value = "";
  messageInput.dispatchEvent(new Event("input"));
  resultPanel.hidden = true;
  messageInput.focus();
});
document.querySelector("#dismiss").addEventListener("click", () => { resultPanel.hidden = true; });

analyzeButton.addEventListener("click", async () => {
  analyzeButton.disabled = true;
  analyzeButton.textContent = "Checking…";
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: messageInput.value }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);

    document.querySelector("#score").textContent = data.score;
    document.querySelector("#risk-label").textContent = data.label;
    document.querySelector("#advice").textContent = data.advice;
    document.querySelector("#score-ring").className = `score-ring ${data.level}`;
    document.querySelector("#findings-title").textContent = data.findings.length
      ? "Signals to notice" : "No common warning signs found";
    document.querySelector("#findings").innerHTML = data.findings.length
      ? data.findings.map((item) => `<article class="finding"><span>!</span><div><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.explanation)}</p></div></article>`).join("")
      : '<p class="no-findings">That is a positive sign, but scams can still look convincing.</p>';
    resultPanel.hidden = false;
    resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    toast.textContent = error.message;
    toast.classList.add("visible");
    setTimeout(() => toast.classList.remove("visible"), 3000);
  } finally {
    analyzeButton.disabled = false;
    analyzeButton.innerHTML = "<span>✳</span> Analyze message";
  }
});
