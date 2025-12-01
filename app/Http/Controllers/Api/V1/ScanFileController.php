<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\ScanFileRequest;
use Illuminate\Support\Facades\Http;

class ScanFileController extends Controller
{
    public function scan(ScanFileRequest $request)
    {
        $response = Http::attach(
            'file',
            file_get_contents($request->file('file')),
            $request->file('file')->getClientOriginalName()
        )->post(config('services.remote_server.file_scanning_url'));

        return response()->json([
            'status' => true,
            'data' => $response->json(),
        ]);
    }
}
