import axios from "axios";

const api = axios.create({ baseURL: "/api" });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("ecdat_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response && err.response.status === 401) {
      localStorage.removeItem("ecdat_token");
      localStorage.removeItem("ecdat_role");
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);

export default api;

export async function login(username: string, password: string) {
  const res = await api.post("/auth/login", { username, password });
  localStorage.setItem("ecdat_token", res.data.access_token);
  localStorage.setItem("ecdat_role", res.data.role);
  return res.data;
}

export function logout() {
  localStorage.removeItem("ecdat_token");
  localStorage.removeItem("ecdat_role");
}

export function isAuthenticated() {
  return !!localStorage.getItem("ecdat_token");
}
