fetch("/api/v1/status")
  .then(function (r) { return r.json(); })
  .then(function (s) {
    document.querySelector(".status").lastChild.textContent =
      s.connection === "connected" ? " Подключено" : " Отключено";
  })
  .catch(function () {});
