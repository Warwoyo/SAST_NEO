<?php

// VULNERABLE: String interpolation
DB::raw("SELECT * FROM table WHERE lower(name) = lower('%{$word}%')");

// VULNERABLE: String concatenation
DB::raw("SELECT * FROM table WHERE id = " . $id);

// SAFE: Normal string
DB::raw("SELECT * FROM table WHERE status = 'active'");

// SAFE: Bound parameter
DB::raw("SELECT * FROM table WHERE id = ?", [$id]);

// SAFE: Casted parameter (assuming the engine isn't evaluating casting right now, but it's structurally just string concat without variables)
DB::raw("SELECT * FROM table WHERE id = " . (int)$id);
