# Publicar este proyecto en GitHub (Ubuntu)

1. Crear un repositorio **vacío y público** llamado `powerbeam-security-lab` en GitHub. **No seleccionar** las opciones de crear README, licencia o `.gitignore` desde GitHub: ya existen archivos preparados localmente (salvo licencia, que se decidirá aparte).
2. Descomprimir la carpeta `powerbeam-security-lab` en una ruta local, sin mezclarla con carpetas que contengan backups o capturas originales.
3. Abrir una terminal **dentro** de la carpeta `powerbeam-security-lab` y ejecutar:

```bash
git init -b main
git status --short
git add README.md .gitignore SECURITY.md GITHUB_SETUP.md docs/ configs/ evidencias/
git diff --cached --stat
git diff --cached --check
git diff --cached        # inspección manual; pulsa q para salir
git commit -m "docs: document PowerBeam security lab days 1 and 2"
```

4. Sustituir `<TU_USUARIO>` por tu identificador en GitHub:

```bash
git remote add origin https://github.com/<TU_USUARIO>/powerbeam-security-lab.git
git branch -M main
git push -u origin main
```

5. Verificar en GitHub que se ven el README, los documentos y los ejemplos. No subir registros reales, backup de airOS ni capturas sin anonimizar.

Si Git exige nombre o correo:

```bash
git config --global user.name "Tu nombre o alias"
git config --global user.email "email-asociado-a-tu-github"
```

También puedes utilizar `gh repo create`, pero no es necesario para este procedimiento. Añadir licencia en una decisión posterior; publicar el código no requiere elegir una automáticamente.

Documentación: https://docs.github.com/es/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github
