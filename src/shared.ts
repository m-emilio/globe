// Messages that we'll send to the client

// Representing a person's position
export type Position = {
  lat: number;
  lng: number;
  id: string;
  ip?: string;
  country?: string;
  city?: string;
  org?: string;
};

export type OutgoingMessage =
  | {
      type: "add-marker";
      position: Position;
    }
  | {
      type: "remove-marker";
      id: string;
    };
