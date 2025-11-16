# DID WebVH Server Documentation

> **Note**: This documentation is hosted on GitHub Pages. See [index.md](./index.md) for the main entry point.

## Documentation

- **[User Manual](./user-manual.md)** - Comprehensive guide to using the DID WebVH Server

## Quick Links

- **Main Documentation**: [index.md](./index.md)
- **User Manual**: [user-manual.md](./user-manual.md)
- **Main README**: [../README.md](../README.md)
- **API Documentation**: Available at `/docs` when the server is running
- **Explorer UI**: Available at `/explorer` when the server is running

## Running Locally

You can preview the documentation locally using Zensical:

### Prerequisites

- Python 3.13 or later
- `uv` package manager

git checkout -b innkeeper-delegation### Setup

1. Install Zensical:
   ```bash
   uv tool install zensical
   ```

2. Serve the documentation:
   ```bash
   # From the project root (where zensical.toml is located)
   uvx zensical serve
   # Or if installed globally:
   zensical serve
   ```

3. Open your browser to `http://localhost:8000`

The site will automatically reload when you make changes to the markdown files.

### Building for Production

To build the static site:

```bash
# From the project root (where zensical.toml is located)
uvx zensical build
# Or if installed globally:
zensical build
```

The built site will be in `docs/site/`.

### Alternative: Simple HTTP Server

If you just want to view the markdown files without Zensical:

```bash
cd docs
python3 -m http.server 8000
# Or with Node.js
npx serve
```

Then open `http://localhost:8000` in your browser.

## GitHub Pages

This documentation is automatically deployed to the `gh-pages` branch when changes are pushed to the `main` branch. The deployment is handled by the GitHub Actions workflow in `.github/workflows/pages.yml`.

The workflow:
1. Installs `uv` and Zensical
2. Builds the static site from the `docs/` directory using Zensical
3. Deploys the built site to the `gh-pages` branch
4. GitHub Pages serves the content from the `gh-pages` branch

