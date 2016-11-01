<?php
namespace Craft;

return [
    'endpoints' => [
        'api/events.json' => [
            'elementType' => 'Entry',
            'criteria' => ['section' => 'events'],
            'transformer' => function(EntryModel $entry) {
                return [
                    'title' => $entry->title,
                    'url' => $entry->url,
                    'jsonUrl' => UrlHelper::getUrl("api/events/{$entry->id}.json")
                ];
            },
            'paginate' => false,
        ],
        'api/events/<entryId:\d+>.json' => function($entryId) {
            return [
                'elementType' => 'Entry',
                'criteria' => ['id' => $entryId],
                'first' => true,
                'transformer' => function(EntryModel $entry) {
                    return [
                        'title' => $entry->title,
                        'url' => $entry->url,
                        'twitchurl' => $entry->twitchurl,
                        'eventnotice' => $entry->eventnotice,
                        'location' => $entry->location,
                        'locationgeo' => $entry->locationgeo,
                        'spectatorcost' => $entry->spectatorcost,
                        'starttime' => $entry->starttime,
                        'subtitle' => $entry->subtitle,
                        'tldr' => $entry->tldr,
                        'tournamentformat' => $entry->tournamentformat,
                        'host' => $entry->host
                    ];
                },
            ];
        },
    ]
];
?>
