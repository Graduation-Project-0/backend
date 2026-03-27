<?php

namespace App\Support\Services;

use App\Models\History;
use App\Models\User;
use Illuminate\Database\Eloquent\Collection;

class HistoryService
{
    public static function createHistory(User|int $user, string $scanType, string|null $result, array $data): History
    {
        return $user->history()
            ->create([
                'scan_type' => $scanType,
                'result' => $result,
                'data' => $data,
            ]);
    }

    public static function getAllUserHistory(User|int $user): Collection|array
    {
        return [
            'file_analysis' => $this->getFileAnalysis($user),
            'url_analysis' => $this->getUrlAnalysis($user),
            'email_analysis' => $this->getEmailAnalysis($user),
            'recent_scans' => $this->getRecentScans($user),
        ];
    }

    private function getFileAnalysis(User|int $user): array
    {
        $history = $user->history()->where('scan_type', 'file')->get();

        return [
            'total' => (clone $history)->count(),
            'malicious' => (clone $history)->where('result', 'malicious')->count(),
            'safe' => (clone $history)->where('result', 'safe')->count(),
            'unknown' => (clone $history)->whereNull('result')->count(),
        ];
    }

    private function getUrlAnalysis(User|int $user): array
    {
        $history = $user->history()->where('scan_type', 'url')->get();

        return [
            'total' => (clone $history)->count(),
            'malicious' => (clone $history)->where('result', 'malicious')->count(),
            'safe' => (clone $history)->where('result', 'safe')->count(),
            'unknown' => (clone $history)->whereNull('result')->count(),
        ];
    }

    private function getEmailAnalysis(User|int $user): array
    {
        $history = $user->history()->where('scan_type', 'email')->get();

        return [
            'total' => (clone $history)->count(),
            'malicious' => (clone $history)->where('result', 'malicious')->count(),
            'safe' => (clone $history)->where('result', 'safe')->count(),
            'unknown' => (clone $history)->whereNull('result')->count(),
        ];
    }

    private function getRecentScans(User|int $user): Collection
    {
        return $user->history()->latest()->take(3)->select('id', 'scan_type', 'result', 'data')->get();
    }
}
