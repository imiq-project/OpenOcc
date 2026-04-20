import {useEffect, useState} from "react";
import {parseMapData} from "@/helper/OpenStreetMapParser";
import {OpenStreetMap} from "@/model/OpenStreetMap";

type OpenStreetMapHookStructure = [
    data: OpenStreetMap | null,
    loading: boolean,
    error: string | null,
];

const useOpenStreetMap = (): OpenStreetMapHookStructure => {

    const [data, setData] = useState<OpenStreetMap | null>(null);
    const [loading, setLoading] = useState<boolean>(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        (async () => {
            setLoading(true);

            try {
                const result = await fetch("api/osm");
                const content = await result.text();
                const map = parseMapData(content);
                setLoading(false);
                setData(map);
            } catch (exception) {
                setLoading(false);
                setError(exception as string);
            }
        })();
    }, []);

    return [
        data,
        loading,
        error
    ];
};

export default useOpenStreetMap;
