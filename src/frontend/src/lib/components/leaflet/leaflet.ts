import { NgModule } from "@angular/core";
import { MapComponent } from "./map.component";
import { MarkerComponent } from "./marker.component";
import { PopupDirective } from "./popup.directive";

@NgModule({
    imports: [
        MapComponent,
        MarkerComponent,
        PopupDirective
    ],
    exports: [
        MapComponent,
        MarkerComponent,
        PopupDirective
    ]
})
export class LeafletModule { }
