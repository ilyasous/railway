import { defineRailway, github, project, service, volume } from "railway/iac";

export default defineRailway(() => {
  const data = volume("data", {
    sizeMB: 1024,
  });

  const web = service("web", {
    source: github("ilyasous/railway"),
    healthcheck: "/health",
    healthcheckTimeout: 300,
    restartPolicyType: "ON_FAILURE",
    restartPolicyMaxRetries: 10,
    volumeMounts: {
      "/data": data,
    },
  });

  return project("Serveur Railway", {
    resources: [web, data],
  });
});
