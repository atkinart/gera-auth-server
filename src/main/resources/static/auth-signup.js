(function () {
  var form = document.getElementById("signup-form");
  var result = document.getElementById("signup-result");

  if (!form || !result) {
    return;
  }

  form.addEventListener("submit", async function (event) {
    event.preventDefault();

    var response;
    var body;
    var message;

    var data = new FormData(form);
    var payload = {
      username: String(data.get("username") || "").trim(),
      email: String(data.get("email") || "").trim(),
      password: String(data.get("password") || "")
    };

    clearNotice();

    try {
      response = await fetch("/api/auth/register", {
        method: "POST",
        headers: {
          "content-type": "application/json"
        },
        body: JSON.stringify(payload)
      });

      body = await response.json().catch(function () {
        return {};
      });

      if (response.status === 201) {
        showNotice("success", "Пользователь создан. Переходим к форме входа...");
        setTimeout(function () {
          window.location.assign("/login");
        }, 900);
        return;
      }

      message = body && body.message ? body.message : "Ошибка регистрации";
      showNotice("error", "Не удалось создать пользователя: " + message);
    } catch (error) {
      showNotice("error", "Ошибка сети: " + (error && error.message ? error.message : "unknown"));
    }
  });

  function showNotice(type, text) {
    result.hidden = false;
    result.className = "notice " + type;
    result.textContent = text;
  }

  function clearNotice() {
    result.hidden = true;
    result.className = "notice";
    result.textContent = "";
  }
})();
