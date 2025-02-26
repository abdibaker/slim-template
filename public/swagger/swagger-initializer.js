window.onload = function () {
  window.ui = SwaggerUIBundle({
    urls: [
      {
        url: "/swagger/swagger.json",
        name: "Default"
      }
    ],
    dom_id: '#swagger-ui',
    filter: true,
    tagsSorter: "alpha",
    validatorUrl: null,
    deepLinking: true,
    presets: [
      SwaggerUIBundle.presets.apis,
      SwaggerUIStandalonePreset
    ],
    plugins: [
      SwaggerUIBundle.plugins.DownloadUrl
    ],
    layout: "StandaloneLayout",
  });
};
