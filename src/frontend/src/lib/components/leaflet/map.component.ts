import {
    AfterContentInit,
    AfterViewInit,
    Component,
    ContentChildren,
    ElementRef,
    input,
    QueryList,
    ViewChild
} from '@angular/core';
import * as L from 'leaflet';
import { MarkerComponent } from './marker.component';

@Component({
    selector: 'leaflet-map',
    template: `<div #mapContainer style="height: 100vh; width: 100%;"></div>`,
})
export class MapComponent implements AfterViewInit, AfterContentInit {

    center = input<L.LatLngExpression>([51.505, -0.09]);
    zoom = input(13)

    @ViewChild('mapContainer', { static: true })
    mapContainer!: ElementRef<HTMLDivElement>;

    @ContentChildren(MarkerComponent)
    markers!: QueryList<MarkerComponent>;

    private map!: L.Map;

    ngAfterViewInit() {
        this.initMap();
    }

    ngAfterContentInit() {
        this.markers.changes.subscribe(() => {
            this.syncMarkers();
        });
    }

    private initMap() {
        this.map = L.map(this.mapContainer.nativeElement)
            .setView(this.center(), this.zoom());

        L.tileLayer(
            'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
            { attribution: '&copy; OpenStreetMap contributors' }
        ).addTo(this.map);

        this.syncMarkers();
    }

    private syncMarkers() {
        if (!this.map) return;

        this.markers.forEach(marker => {
            marker.addToMap(this.map);
        });
    }
}
