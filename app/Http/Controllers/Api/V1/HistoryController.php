<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Support\Services\HistoryService;
use Illuminate\Http\Request;

class HistoryController extends Controller
{
    public function index(Request $request)
    {
        return response()->json([
            'status' => true,
            'data' => HistoryService::getAllUserHistory($request->user()),
        ]);
    }
}
