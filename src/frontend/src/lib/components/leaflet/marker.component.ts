import {
    AfterContentInit,
    Component,
    ContentChild,
    Input,
    OnDestroy,
    ViewContainerRef,
    EmbeddedViewRef
} from '@angular/core';
import * as L from 'leaflet';
import { PopupDirective } from './popup.directive';

@Component({
    selector: 'leaflet-marker',
    template: ``,
})
export class MarkerComponent implements AfterContentInit, OnDestroy {

    @Input() lat!: number;
    @Input() lng!: number;

    @ContentChild(PopupDirective)
    popup?: PopupDirective;

    private marker?: L.Marker;
    private popupView?: EmbeddedViewRef<any>;

    constructor(private vcr: ViewContainerRef) { }

    ngAfterContentInit() { }

    addToMap(map: L.Map) {
        if (this.marker) return;

        this.marker = L.marker([this.lat, this.lng]).addTo(map);

        if (this.popup) {
            this.attachAngularPopup();
        }
    }

    private attachAngularPopup() {
        if (!this.popup || !this.marker) return;

        // Create Angular view from template
        this.popupView = this.vcr.createEmbeddedView(
            this.popup.template,
            { $implicit: { title: 'Dynamic Title' } }
        );

        this.popupView.detectChanges();

        // Create wrapper div
        const container = document.createElement('div');

        this.popupView.rootNodes.forEach(node => {
            container.appendChild(node);
        });

        this.marker.bindPopup(container, { closeOnClick: false, autoClose: false }).openPopup();
    }

    ngOnDestroy() {
        if (this.popupView) {
            this.popupView.destroy();
        }

        if (this.marker) {
            this.marker.remove();
        }
    }
}
