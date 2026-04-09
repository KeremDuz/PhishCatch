# Branching Strategy

## Ana Branch'ler
- `main`: Her zaman deploy edilebilir stabil branch
- `develop`: Günlük entegrasyon branch'i

## Yardımcı Branch'ler
- `feature/<scope>-<name>`
- `release/<version>`
- `hotfix/<name>`

## Akış
1. `develop` üzerinden feature branch aç
2. Feature branch'e commit/push yap
3. `develop` için PR aç
4. Release döneminde `release/*` aç
5. `release/*` -> `main` merge + tag
6. `main` değişikliklerini geri `develop`e al
